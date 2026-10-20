from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest


def _load_qemu_runtime_build():
    script = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "qemu_runtime_build.py"
    spec = importlib.util.spec_from_file_location("qemu_runtime_build", script)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the QEMU runtime build helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


qemu_runtime_build = _load_qemu_runtime_build()


def test_source_audit_exports_container_owned_evidence_without_writable_host_mount(
    monkeypatch, tmp_path: Path
) -> None:
    sources = tmp_path / "debian.sources"
    sources.write_text("Types: deb\nURI: https://snapshot.debian.org/one\n\nTypes: deb\n")
    audit = tmp_path / "audit"
    calls: list[list[str]] = []

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[:2] == ["docker", "cp"]:
            target = Path(args[-1])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("sanitized fixture evidence\n", encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(qemu_runtime_build, "run", fake_run)

    qemu_runtime_build.source_audit_container(sources, audit)

    create_calls = [args for args in calls if args[:2] == ["docker", "create"]]
    assert len(create_calls) == 1, "audit must run in a named container for safe evidence copying"
    create = create_calls[0]
    source_mount = next(arg for arg in create if arg.startswith("type=bind,"))
    tmpfs_index = create.index("--tmpfs")
    assert create[tmpfs_index + 1] == "/tmp:rw,nosuid,nodev,noexec,size=512m,mode=1777"
    assert "install -d -m 0700 /audit" in create[-1]
    assert "install -d -m 0700 /audit/source" in create[-1]
    assert "install -d -m 0700 /audit/source /audit/unpacked" not in create[-1]
    assert "FIRMWARE_FREE_PHASE_FAILURE" in create[-1]
    assert 'tail -n 12 "$failure_log"' in create[-1]
    assert "exec 3>&2" in create[-1]
    assert "printf '%s\\n' \"$phase\" > /audit/phase" in create[-1]
    assert "printf '%s\\n' \"$failure_log\" > /audit/failure-log" in create[-1]
    assert "4CB50190207B4758A3F73A796ED0E7B82643E131" in create[-1]
    assert "ED541312A33F1128F10B1C6C54404762BBB6E853" in create[-1]
    assert "-o APT::Sandbox::User=root" in create[-1]
    assert "-o Dpkg::Use-Pty=false" in create[-1]
    assert "-o Dir::Log=/dev/null" in create[-1]
    assert 'source_tmp="$(mktemp -d /tmp/qemu-source-download.XXXXXX)"' in create[-1]
    assert 'cd "$source_tmp"' in create[-1]
    assert 'apt-get "${apt_opts[@]}" source --download-only --only-source' in create[-1]
    assert "sha256sum --check --status" in create[-1]
    assert " && printf" not in create[-1]
    assert 'mv "${dsc[0]}" /audit/source/' in create[-1]
    assert "/audit/source/qemu_7.2+dfsg-7+deb12u18.dsc" in create[-1]
    assert source_mount.endswith(",readonly")
    assert not any("dst=/audit" in arg and arg.startswith("type=bind,") for arg in create)
    assert "--cap-drop=ALL" in create
    assert create[create.index("--security-opt") + 1] == "no-new-privileges:true"
    assert "--rm" not in create

    operations = [args[:2] for args in calls]
    assert operations.index(["docker", "create"]) < operations.index(["docker", "start"])
    assert operations.index(["docker", "start"]) < operations.index(["docker", "cp"])
    assert operations[-1] == ["docker", "rm"]
    assert (audit / "inrelease.tsv").is_file()
    assert (audit / "source" / "qemu_7.2+dfsg.orig.tar.xz").is_file()


def test_source_audit_failure_copies_container_logs_before_removing_container(
    monkeypatch, tmp_path: Path
) -> None:
    sources = tmp_path / "debian.sources"
    sources.write_text("Types: deb\nURI: https://snapshot.debian.org/one\n\nTypes: deb\n")
    audit = tmp_path / "audit"
    calls: list[list[str]] = []

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[:2] == ["docker", "start"]:
            raise qemu_runtime_build.StopBuild("container command failed")
        if args[:2] == ["docker", "cp"]:
            source = args[-2].split(":", 1)[-1]
            target = Path(args[-1])
            if source == "/audit/apt-update.log":
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("apt update diagnostic fixture\n", encoding="utf-8")
                return subprocess.CompletedProcess(args, 0, stdout="")
            return subprocess.CompletedProcess(args, 1, stdout="not present")
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(qemu_runtime_build, "run", fake_run)

    with pytest.raises(qemu_runtime_build.StopBuild, match="apt update diagnostic fixture"):
        qemu_runtime_build.source_audit_container(sources, audit)

    operations = [args[:2] for args in calls]
    assert operations[-1] == ["docker", "rm"]
    assert (audit / "apt-update.log").is_file()


def test_source_audit_attempts_cleanup_if_create_times_out_after_daemon_creation(
    monkeypatch, tmp_path: Path
) -> None:
    sources = tmp_path / "debian.sources"
    sources.write_text("Types: deb\nURI: https://snapshot.debian.org/one\n\nTypes: deb\n")
    calls: list[list[str]] = []

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[:2] == ["docker", "create"]:
            raise subprocess.TimeoutExpired(args, timeout=120)
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(qemu_runtime_build, "run", fake_run)

    with pytest.raises(subprocess.TimeoutExpired):
        qemu_runtime_build.source_audit_container(sources, tmp_path / "audit")

    assert calls[-1][:2] == ["docker", "rm"]
    assert calls[-1][2:4] == ["--force", calls[0][calls[0].index("--name") + 1]]


def test_source_audit_rejects_evidence_larger_than_documented_limit(
    monkeypatch, tmp_path: Path
) -> None:
    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        Path(args[-1]).write_bytes(
            b"x" * (qemu_runtime_build.AUDIT_FILE_MAX_BYTES["inrelease.tsv"] + 1)
        )
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(qemu_runtime_build, "run", fake_run)

    with pytest.raises(qemu_runtime_build.StopBuild, match="exceeds its size limit"):
        qemu_runtime_build.copy_audit_files(
            "qemu-source-audit-test",
            tmp_path,
            (("/audit/inrelease.tsv", "inrelease.tsv"),),
            required=True,
        )


def test_build_container_uses_only_hardened_read_only_source_mount(tmp_path: Path) -> None:
    args = qemu_runtime_build.build_container_args(
        tmp_path / "inputs", "set -euo pipefail\ntrue", "qemu-build-test"
    )

    assert args[:3] == ["docker", "create", "--name"]
    assert "--network" in args
    assert args[args.index("--network") + 1] == "bridge"
    assert "--cap-drop=ALL" in args
    assert args[args.index("--security-opt") + 1] == "no-new-privileges:true"
    assert args[args.index("--memory") + 1] == "6g"
    assert args[args.index("--cpus") + 1] == "2"
    mounts = [arg for arg in args if arg.startswith("type=bind,")]
    assert len(mounts) == 1
    assert mounts[0].endswith(",dst=/inputs,readonly")
    tmpfs_mounts = [args[index + 1] for index, arg in enumerate(args) if arg == "--tmpfs"]
    assert tmpfs_mounts == [
        "/tmp:rw,nosuid,nodev,noexec,size=512m,mode=1777",
        "/build:rw,nosuid,nodev,exec,size=6g,mode=0755",
    ]
    assert not any(arg.startswith("--device") for arg in args)
    assert "--privileged" not in args
    assert "-p" not in args
    assert args[-4:] == [
        qemu_runtime_build.BASE_IMAGE,
        "/bin/bash",
        "-euc",
        "set -euo pipefail\ntrue",
    ]


def test_execution_container_is_networkless_read_only_and_resource_bounded(
    tmp_path: Path,
) -> None:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    inputs.chmod(0o700)
    if os.name == "posix":
        with pytest.raises(qemu_runtime_build.StopBuild, match="not traversable"):
            qemu_runtime_build.execution_container_args(
                inputs, "set -euo pipefail\ntrue", "qemu-smoke-test"
            )
    inputs.chmod(0o711)
    args = qemu_runtime_build.execution_container_args(
        inputs, "set -euo pipefail\ntrue", "qemu-smoke-test"
    )

    assert args[:3] == ["docker", "create", "--name"]
    assert args[args.index("--network") + 1] == "none"
    assert "--cap-drop=ALL" in args
    assert args[args.index("--security-opt") + 1] == "no-new-privileges:true"
    assert "--read-only" in args
    assert args[args.index("--user") + 1] == "65534:65534"
    assert args[args.index("--memory") + 1] == "256m"
    assert args[args.index("--cpus") + 1] == "1"
    assert args[args.index("--pids-limit") + 1] == "16"
    mounts = [arg for arg in args if arg.startswith("type=bind,")]
    assert len(mounts) == 1
    assert mounts[0].endswith(",dst=/inputs,readonly")
    assert not any(arg.startswith("--device") for arg in args)
    assert "--privileged" not in args
    assert not any("docker.sock" in arg for arg in args)


def test_execution_smoke_command_checks_success_failure_and_timeout() -> None:
    command = qemu_runtime_build.execution_smoke_container_command()

    assert "qemu=/inputs/qemu-mipsel" in command
    assert '"$qemu" --version' in command
    assert "ulimit -c 0" in command
    assert 'timeout --signal=TERM --kill-after=1s 5s "$qemu" --version' in command
    assert "version_status=$?" in command
    assert "QEMU_VERSION_EXIT_STATUS=%s" in command
    assert "QEMU_STRACE=1" in command
    assert 'timeout --signal=TERM --kill-after=1s 5s "$qemu" "$guest"' in command
    assert "ulimit -f 8192" in command
    assert "QEMU_LOG=guest_errors,in_asm QEMU_LOG_FILENAME=/tmp/success.qemu.log" in command
    assert "head -c 4096 /tmp/success.qemu.log" in command
    assert "cat /tmp/success.trace.stdout >>/tmp/success.stderr" in command
    assert "cat /tmp/success.trace.stderr >>/tmp/success.stderr" in command
    assert "SYNTHETIC_SUCCESS_DIAGNOSTIC_STDERR=%s\\n" in command
    assert "/inputs/mips32le-execution-smoke.elf" in command
    assert "--fail" in command
    assert "--timeout" in command
    assert "timeout --signal=TERM --kill-after=1s 2s" in command
    assert "--network" not in command


@pytest.mark.parametrize(
    ("exit_status", "stderr", "stdout_matches", "expected"),
    [
        (1, "qemu: Invalid ELF image for this architecture", False, "guest-elf-loading"),
        (1, "qemu: error while loading: Permission denied", False, "permission-error"),
        (1, "mmap: Cannot allocate memory", False, "memory-or-address-mapping"),
        (1, "write(1, ...) = -1 errno=13", False, "guest-syscall-failure"),
        (
            139,
            "qemu: uncaught target signal 11 (Segmentation fault)",
            False,
            "qemu-process-failure",
        ),
        (0, "", False, "stdout-mismatch"),
    ],
)
def test_execution_failure_diagnostic_distinguishes_qemu_failure_classes(
    exit_status: int, stderr: str, stdout_matches: bool, expected: str
) -> None:
    assert (
        qemu_runtime_build.classify_execution_failure(exit_status, stderr, stdout_matches)
        == expected
    )


def test_execution_failure_diagnostic_is_bounded_and_removes_control_characters() -> None:
    sanitized = qemu_runtime_build.sanitize_execution_diagnostic("bad\x1b[31m ELF\n" + "x" * 900)

    assert len(sanitized) <= qemu_runtime_build.EXECUTION_DIAGNOSTIC_MAX_CHARS
    assert "\x1b" not in sanitized
    assert "\n" not in sanitized


def test_execution_failure_diagnostic_parser_reports_sanitized_memory_failure() -> None:
    output = "\n".join(
        [
            "SYNTHETIC_SUCCESS_DIAGNOSTIC_EXIT_STATUS=1",
            "SYNTHETIC_SUCCESS_DIAGNOSTIC_STDOUT_MATCH=false",
            "SYNTHETIC_SUCCESS_DIAGNOSTIC_STDOUT_BYTES=0",
            "SYNTHETIC_SUCCESS_DIAGNOSTIC_STDOUT_SHA256=" + "a" * 64,
            "SYNTHETIC_SUCCESS_DIAGNOSTIC_STDOUT_TEXT=",
            "SYNTHETIC_SUCCESS_DIAGNOSTIC_STDERR=mmap failed at "
            "/inputs/mips32le-execution-smoke.elf: ENOMEM",
        ]
    )

    diagnostic = qemu_runtime_build.parse_execution_failure_diagnostic(output)

    assert diagnostic is not None
    assert diagnostic["category"] == "memory-or-address-mapping"
    assert diagnostic["stderr"] == "mmap failed at <synthetic-guest>: ENOMEM"


def test_execution_failure_diagnostic_classifies_qemu_loader_stdout() -> None:
    output = "\n".join(
        [
            "SYNTHETIC_SUCCESS_DIAGNOSTIC_EXIT_STATUS=1",
            "SYNTHETIC_SUCCESS_DIAGNOSTIC_STDOUT_MATCH=false",
            "SYNTHETIC_SUCCESS_DIAGNOSTIC_STDOUT_BYTES=56",
            "SYNTHETIC_SUCCESS_DIAGNOSTIC_STDOUT_SHA256=" + "b" * 64,
            "SYNTHETIC_SUCCESS_DIAGNOSTIC_STDOUT_TEXT=Error while loading "
            "/inputs/mips32le-execution-smoke.elf: Permission denied",
            "SYNTHETIC_SUCCESS_DIAGNOSTIC_STDERR=",
        ]
    )

    diagnostic = qemu_runtime_build.parse_execution_failure_diagnostic(output)

    assert diagnostic is not None
    assert diagnostic["category"] == "permission-error"
    assert diagnostic["stdout"] == "Error while loading <synthetic-guest>: Permission denied"


def test_only_execution_build_compiles_the_first_party_guest() -> None:
    reference = qemu_runtime_build.read_reference()

    ordinary = qemu_runtime_build.build_container_command(reference)
    smoke = qemu_runtime_build.build_container_command(reference, include_smoke_guest=True)

    assert "mipsel-linux-gnu-gcc -static -march=mips32 -mabi=32 -EL" not in ordinary
    assert "mipsel-linux-gnu-gcc -static -march=mips32 -mabi=32 -EL" in smoke
    assert "/inputs/lab/fixtures/mips32le_execution_smoke.c" in smoke
    assert "mark_phase synthetic-guest-build /audit/synthetic-guest-build.log" in smoke
    assert "measure-smoke-guest" in smoke
    assert "mark_phase synthetic-guest-artifact-staging" in smoke
    assert "/audit/execution-inputs/qemu-mipsel" in smoke
    assert "/audit/execution-inputs/mips32le-execution-smoke.elf" in smoke


def test_synthetic_guest_elf_requires_static_mips32le_o32(monkeypatch, tmp_path: Path) -> None:
    guest = tmp_path / "guest.elf"
    guest.write_bytes(b"synthetic ELF fixture")
    header = """ELF Header:
  Class:                             ELF32
  Data:                              2's complement, little endian
  Type:                              EXEC (Executable file)
  Machine:                           MIPS R3000
  Flags:                             0x50001007, noreorder, pic, cpic, o32, mips32
"""

    def fake_tool_output(args: list[str]) -> str:
        if args[:2] == ["mipsel-linux-gnu-readelf", "-h"]:
            return header
        if args[:2] == ["mipsel-linux-gnu-readelf", "-l"]:
            return "Program Headers:\n  LOAD 0x000000 0x00400000 0x00400000\n"
        raise AssertionError(args)

    monkeypatch.setattr(qemu_runtime_build, "_tool_output", fake_tool_output)

    evidence = qemu_runtime_build.synthetic_guest_elf_evidence(guest)

    assert evidence["elf_class"] == "ELF32"
    assert evidence["elf_data"] == "little endian"
    assert evidence["machine"] == "MIPS R3000"
    assert evidence["abi"] == "o32"
    assert evidence["isa"] == "mips32"
    assert evidence["has_interpreter"] is False
    assert evidence["sha256"] == qemu_runtime_build.digest(guest)


def test_synthetic_guest_elf_rejects_interpreted_or_wrong_abi(monkeypatch, tmp_path: Path) -> None:
    guest = tmp_path / "guest.elf"
    guest.write_bytes(b"synthetic ELF fixture")
    header = """ELF Header:
  Class:                             ELF32
  Data:                              2's complement, little endian
  Type:                              EXEC (Executable file)
  Machine:                           MIPS R3000
  Flags:                             0x50001007, noreorder, pic, cpic, n32, mips32
"""

    def fake_tool_output(args: list[str]) -> str:
        return (
            header
            if args[:2] == ["mipsel-linux-gnu-readelf", "-h"]
            else "INTERP 0x000001 0x00400000"
        )

    monkeypatch.setattr(qemu_runtime_build, "_tool_output", fake_tool_output)

    with pytest.raises(qemu_runtime_build.StopBuild, match="static MIPS32 little-endian O32"):
        qemu_runtime_build.synthetic_guest_elf_evidence(guest)


def test_synthetic_guest_elf_preserves_the_reported_mips32r2_isa(
    monkeypatch, tmp_path: Path
) -> None:
    guest = tmp_path / "guest.elf"
    guest.write_bytes(b"synthetic ELF fixture")
    header = """ELF Header:
  Class:                             ELF32
  Data:                              2's complement, little endian
  Type:                              EXEC (Executable file)
  Machine:                           MIPS R3000
  Flags:                             0x70001007, noreorder, pic, cpic, o32, mips32r2
"""

    def fake_tool_output(args: list[str]) -> str:
        if args[:2] == ["mipsel-linux-gnu-readelf", "-h"]:
            return header
        return "Program Headers:\n  LOAD\n"

    monkeypatch.setattr(qemu_runtime_build, "_tool_output", fake_tool_output)

    evidence = qemu_runtime_build.synthetic_guest_elf_evidence(guest)

    assert evidence["architecture"] == "MIPS32 little-endian"
    assert evidence["abi"] == "o32"
    assert evidence["isa"] == "mips32r2"


def test_execution_container_inspection_rejects_network_or_mount_drift(tmp_path: Path) -> None:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    inspection = [
        {
            "HostConfig": {
                "NetworkMode": "none",
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "ReadonlyRootfs": True,
                "Privileged": False,
                "Memory": 256 * 1024**2,
                "MemorySwap": 256 * 1024**2,
                "NanoCpus": 1_000_000_000,
                "PidsLimit": 16,
                "Devices": [],
                "PortBindings": {},
                "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=32m,mode=1777"},
            },
            "Config": {"User": "65534:65534", "Image": qemu_runtime_build.BASE_IMAGE},
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": str(inputs.resolve()),
                    "Destination": "/inputs",
                    "RW": False,
                },
                {"Type": "tmpfs", "Destination": "/tmp", "RW": True},
            ],
        }
    ]

    limits = qemu_runtime_build.validate_execution_container_inspect(inspection, inputs)

    assert limits["network_mode"] == "none"
    assert limits["capabilities"] == "all dropped"
    assert limits["privileged"] is False
    inspection[0]["HostConfig"]["NetworkMode"] = "bridge"
    with pytest.raises(qemu_runtime_build.StopBuild, match="isolation limits"):
        qemu_runtime_build.validate_execution_container_inspect(inspection, inputs)


def test_execution_output_receipt_checks_determinism_failure_and_timeout() -> None:
    stdout = b"SNOWSKY_MIPS32LE_EXECUTION_OK\n"
    output = "\n".join(
        [
            "QEMU_VERSION=qemu-mipsel version 7.2.18 (Debian 1:7.2+dfsg-7+deb12u18)",
            "SUCCESS_EXIT_STATUS=0",
            f"SUCCESS_STDOUT_BYTES={len(stdout)}",
            f"SUCCESS_STDOUT_SHA256={qemu_runtime_build.hashlib.sha256(stdout).hexdigest()}",
            "EXPECTED_FAILURE_EXIT_STATUS=23",
            "TIMEOUT_EXIT_STATUS=124",
            "TIMEOUT_SECONDS=2",
        ]
    )

    outcome = qemu_runtime_build.parse_execution_smoke_output(output)

    assert outcome["success"]["stdout_matches_expected"] is True
    assert outcome["expected_failure"]["reported"] is True
    assert outcome["timeout"]["reported"] is True
    with pytest.raises(qemu_runtime_build.StopBuild, match="expected outcomes"):
        qemu_runtime_build.parse_execution_smoke_output(
            output.replace("TIMEOUT_EXIT_STATUS=124", "TIMEOUT_EXIT_STATUS=0")
        )


def test_execution_smoke_runs_only_after_inspection_and_removes_container(
    monkeypatch, tmp_path: Path
) -> None:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    qemu = inputs / "qemu-mipsel"
    guest = inputs / "mips32le-execution-smoke.elf"
    qemu.write_bytes(b"qemu fixture")
    guest.write_bytes(b"guest fixture")
    stdout = b"SNOWSKY_MIPS32LE_EXECUTION_OK\n"
    output = "\n".join(
        [
            "QEMU_VERSION=qemu-mipsel version 7.2.18 (Debian 1:7.2+dfsg-7+deb12u18)",
            "SUCCESS_EXIT_STATUS=0",
            f"SUCCESS_STDOUT_BYTES={len(stdout)}",
            f"SUCCESS_STDOUT_SHA256={qemu_runtime_build.hashlib.sha256(stdout).hexdigest()}",
            "EXPECTED_FAILURE_EXIT_STATUS=23",
            "TIMEOUT_EXIT_STATUS=124",
            "TIMEOUT_SECONDS=2",
        ]
    )
    inspection = [
        {
            "HostConfig": {
                "NetworkMode": "none",
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "ReadonlyRootfs": True,
                "Privileged": False,
                "Memory": 256 * 1024**2,
                "MemorySwap": 256 * 1024**2,
                "NanoCpus": 1_000_000_000,
                "PidsLimit": 16,
                "Devices": [],
                "PortBindings": {},
                "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=32m,mode=1777"},
            },
            "Config": {"User": "65534:65534", "Image": qemu_runtime_build.BASE_IMAGE},
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": str(inputs.resolve()),
                    "Destination": "/inputs",
                    "RW": False,
                },
                {"Type": "tmpfs", "Destination": "/tmp", "RW": True},
            ],
        }
    ]
    calls: list[list[str]] = []
    inspect_count = 0

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal inspect_count
        calls.append(args)
        if args[:2] == ["docker", "inspect"]:
            inspect_count += 1
            result = (
                inspection if inspect_count == 1 else [{"State": {"Running": False, "ExitCode": 0}}]
            )
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps(result))
        if args[:3] == ["docker", "start", "--attach"]:
            return subprocess.CompletedProcess(args, 0, stdout=output)
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(qemu_runtime_build, "run", fake_run)
    evidence = {
        "artifacts": [
            {"name": "qemu-mipsel", "sha256": qemu_runtime_build.digest(qemu)},
        ],
        "synthetic_guest": {"elf": {"sha256": qemu_runtime_build.digest(guest)}},
    }

    outcome = qemu_runtime_build.run_execution_smoke_container(inputs, evidence)

    assert outcome["container_exit_status"] == 0
    assert outcome["process_terminated_cleanly"] is True
    assert ["docker", "rm", "--force"] == calls[-1][:3]
    first_inspect = next(call for call in calls if call[:2] == ["docker", "inspect"])
    start = next(call for call in calls if call[:2] == ["docker", "start"])
    assert calls.index(first_inspect) < calls.index(start)


def test_execution_smoke_receipt_keeps_stock_capabilities_unverified() -> None:
    receipt = qemu_runtime_build.build_execution_smoke_receipt(
        {
            "artifacts": [{"name": "qemu-mipsel", "bytes": 12, "sha256": "a" * 64}],
            "input_manifest_sha256": "f" * 64,
            "synthetic_guest": {
                "status": "synthetic-static-guest-built",
                "source": {"sha256": "b" * 64},
                "elf": {"sha256": "c" * 64},
            },
            "toolchain": {"mipsel": {"target": "mipsel-linux-gnu"}},
        },
        {"duration_seconds": 0.2, "isolation": {"network_mode": "none"}},
        {"capacity_status": "sufficient"},
        {"index_digest": "sha256:" + "d" * 64},
        {"emulator/docker/qemu/snowsky-disc-devices.patch": "e" * 64},
        {"source_archives": []},
    )

    assert receipt["status"] == "synthetic-execution-passed"
    assert (
        "static MIPS32 little-endian O32 guest process execution"
        in receipt["verified_capabilities"]
    )
    assert "stock V2.57 firmware compatibility or boot" in receipt["unverified_capabilities"]
    assert receipt["runtime_boundaries"]["firmware_processed"] is False
    assert receipt["runtime_boundaries"]["compatibility_claimed"] is False


def test_build_report_allowlist_contains_only_sanitized_receipt() -> None:
    assert qemu_runtime_build.BUILD_EVIDENCE_FILES == (
        ("/audit/build-evidence.json", "build-evidence.json"),
    )


def test_build_recipe_uses_the_pinned_target_without_runtime_or_guest_commands() -> None:
    command = qemu_runtime_build.build_container_command(qemu_runtime_build.read_reference())

    assert "dpkg-source -x qemu_7.2+dfsg-7+deb12u18.dsc" in command
    assert "patch --batch --forward --fuzz=0 -p1" in command
    assert "grep -Eiq 'fuzz|offset|reversed|previously applied|skipping'" in command
    assert "FIRMWARE_FREE_PHASE_FAILURE" in command
    assert 'tail -n 12 "$failure_log"' in command
    assert "exec 3>&2" in command
    assert "printf '%s\\n' \"$phase\" > /audit/phase" in command
    assert "printf '%s\\n' \"$failure_log\" > /audit/failure-log" in command
    assert "./configure" in command
    assert "ninja -j2 -C build qemu-mipsel" in command
    assert "4CB50190207B4758A3F73A796ED0E7B82643E131" in command
    assert "ED541312A33F1128F10B1C6C54404762BBB6E853" in command
    assert "build_shims.sh" in command
    assert "APT::Sandbox::User=root" in command
    assert "Dpkg::Use-Pty=false" in command
    assert "Dir::Log=/dev/null" in command
    assert "apt download fakeroot libfakeroot" in command
    assert "fakeroot-sysv_*.deb" not in command
    assert "dpkg-deb --fsys-tarfile" in command
    assert "tar --no-same-owner" in command
    assert '"$fakeroot_bin" --lib "$fakeroot_library" --faked "$fakeroot_daemon" --' in command
    assert 'apt-get "${apt_opts[@]}" install -y --no-install-recommends' in command
    assert "binfmt" not in command
    assert "qemu-user-static" not in command
    assert "qemu-mipsel -version" not in command
    assert "qemu-mipsel-static" not in command


def test_build_reference_pins_capability_free_dpkg_bootstrap() -> None:
    reference = qemu_runtime_build.read_reference()
    build_inputs = reference["buildInputs"]

    assert set(qemu_runtime_build.FAKEROOT_BOOTSTRAP_PACKAGES).issubset(
        build_inputs["nativeBuildPackageRequests"]
    )
    strategy = build_inputs["packageInstallStrategy"]
    assert tuple(strategy["bootstrapPackages"]) == qemu_runtime_build.FAKEROOT_BOOTSTRAP_PACKAGES
    assert qemu_runtime_build.FAKEROOT_BOOTSTRAP_PACKAGES == ("fakeroot", "libfakeroot")
    assert strategy["installer"] == "fakeroot"
    assert strategy["containerCapabilities"] == "all dropped"


def test_fakeroot_bootstrap_receipt_requires_exact_package_hashes(tmp_path: Path) -> None:
    receipt = tmp_path / "fakeroot-bootstrap.tsv"
    receipt.write_text(
        "fakeroot\t1.31-1.2\tamd64\t42000\t" + "a" * 64 + "\n"
        "libfakeroot\t1.31-1.2\tamd64\t30000\t" + "b" * 64 + "\n",
        encoding="utf-8",
    )

    assert qemu_runtime_build.read_fakeroot_bootstrap_evidence(receipt) == [
        {
            "package": "fakeroot",
            "version": "1.31-1.2",
            "architecture": "amd64",
            "bytes": 42000,
            "sha256": "a" * 64,
        },
        {
            "package": "libfakeroot",
            "version": "1.31-1.2",
            "architecture": "amd64",
            "bytes": 30000,
            "sha256": "b" * 64,
        },
    ]

    receipt.write_text(
        "fakeroot\t1.31-1.2\tamd64\t42000\t" + "a" * 64 + "\n",
        encoding="utf-8",
    )
    with pytest.raises(qemu_runtime_build.StopBuild, match="bootstrap package set"):
        qemu_runtime_build.read_fakeroot_bootstrap_evidence(receipt)


def test_build_container_copies_only_validated_json_then_removes_container(
    monkeypatch, tmp_path: Path
) -> None:
    artifact = {
        "name": "qemu-mipsel",
        "bytes": 1024,
        "sha256": "a" * 64,
        "elf_class": "ELF64",
        "elf_data": "little endian",
        "machine": "Advanced Micro Devices X86-64",
        "flags": "0x0",
        "has_interpreter": False,
    }
    shims = [
        {
            "name": name,
            "bytes": 128,
            "sha256": "b" * 64,
            "elf_class": "ELF32",
            "elf_data": "little endian",
            "machine": "MIPS R3000",
            "flags": "0x70001407",
            "has_interpreter": False,
        }
        for name in ("fbshim.so", "asndshim.so", "tinyshim.so", "mqshim.so")
    ]
    evidence = {
        "schema_version": "firmware-free-qemu-runtime-build/v1",
        "status": "build-passed-binaries-ephemeral",
        "artifacts": [artifact, *shims],
        "retention": {"compiled_binaries_published": False},
    }
    calls: list[list[str]] = []

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[:2] == ["docker", "cp"]:
            target = Path(args[-1])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(evidence), encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(qemu_runtime_build, "run", fake_run)
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    output = tmp_path / "report" / "build-evidence.json"

    result = qemu_runtime_build.run_build_container(
        inputs, output, qemu_runtime_build.read_reference()
    )

    assert result["status"] == "build-passed-binaries-ephemeral"
    copied = [args[-2] for args in calls if args[:2] == ["docker", "cp"]]
    assert len(copied) == 1
    assert copied[0].endswith(":/audit/build-evidence.json")
    assert [args[:2] for args in calls][-1] == ["docker", "rm"]


def test_build_container_stages_synthetic_guest_as_read_only_executable(
    monkeypatch, tmp_path: Path
) -> None:
    qemu_bytes = b"synthetic qemu"
    guest_bytes = b"synthetic mips elf"
    qemu_artifact = {
        "name": "qemu-mipsel",
        "bytes": len(qemu_bytes),
        "sha256": qemu_runtime_build.hashlib.sha256(qemu_bytes).hexdigest(),
        "elf_class": "ELF64",
        "elf_data": "little endian",
        "machine": "Advanced Micro Devices X86-64",
        "flags": "0x0",
        "has_interpreter": False,
    }
    shims = [
        {
            "name": name,
            "bytes": 128,
            "sha256": "b" * 64,
            "elf_class": "ELF32",
            "elf_data": "little endian",
            "machine": "MIPS R3000",
            "flags": "0x70001407",
            "has_interpreter": False,
        }
        for name in ("fbshim.so", "asndshim.so", "tinyshim.so", "mqshim.so")
    ]
    guest_evidence = {
        "schema_version": "firmware-free-mips32le-synthetic-guest/v1",
        "status": "synthetic-static-guest-built",
        "source": {"sha256": qemu_runtime_build.digest(qemu_runtime_build.SMOKE_GUEST_SOURCE_PATH)},
        "elf": {
            "bytes": len(guest_bytes),
            "sha256": qemu_runtime_build.hashlib.sha256(guest_bytes).hexdigest(),
            "elf_class": "ELF32",
            "elf_data": "little endian",
            "machine": "MIPS R3000",
            "abi": "o32",
            "isa": "mips32",
            "has_interpreter": False,
        },
    }
    build_evidence = {
        "schema_version": "firmware-free-qemu-runtime-build/v1",
        "status": "build-passed-binaries-ephemeral",
        "artifacts": [qemu_artifact, *shims],
        "synthetic_guest": guest_evidence,
        "retention": {"compiled_binaries_published": False},
    }
    binaries = {
        "/audit/execution-inputs/qemu-mipsel": qemu_bytes,
        "/audit/execution-inputs/mips32le-execution-smoke.elf": guest_bytes,
    }

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["docker", "cp"]:
            source = args[-2].split(":", 1)[-1]
            target = Path(args[-1])
            target.parent.mkdir(parents=True, exist_ok=True)
            if source == "/audit/build-evidence.json":
                target.write_text(json.dumps(build_evidence), encoding="utf-8")
            elif source == "/audit/synthetic-guest-evidence.json":
                target.write_text(json.dumps(guest_evidence), encoding="utf-8")
            else:
                target.write_bytes(binaries[source])
        return subprocess.CompletedProcess(args, 0, stdout="")

    copy_modes: list[tuple[str, bool]] = []
    copy_execution_binary = qemu_runtime_build.copy_execution_binary

    def recording_copy(
        container_name: str,
        container_path: str,
        target: Path,
        expected_sha256: str,
        maximum_bytes: int,
        *,
        executable: bool,
    ) -> None:
        copy_modes.append((container_path, executable))
        copy_execution_binary(
            container_name,
            container_path,
            target,
            expected_sha256,
            maximum_bytes,
            executable=executable,
        )

    monkeypatch.setattr(qemu_runtime_build, "run", fake_run)
    monkeypatch.setattr(qemu_runtime_build, "copy_execution_binary", recording_copy)
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    smoke_inputs = tmp_path / "smoke-inputs"
    smoke_inputs.mkdir()

    qemu_runtime_build.run_build_container(
        inputs,
        tmp_path / "report" / "build-evidence.json",
        qemu_runtime_build.read_reference(),
        smoke_inputs_dir=smoke_inputs,
    )

    assert copy_modes == [
        ("/audit/execution-inputs/qemu-mipsel", True),
        ("/audit/execution-inputs/mips32le-execution-smoke.elf", True),
    ]
    assert (smoke_inputs / "mips32le-execution-smoke.elf").read_bytes() == guest_bytes


def test_failed_build_reports_bounded_container_logs_before_cleanup(
    monkeypatch, tmp_path: Path
) -> None:
    calls: list[list[str]] = []

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[:2] == ["docker", "start"]:
            raise qemu_runtime_build.StopBuild("command failed (100): docker start")
        if args[:2] == ["docker", "cp"]:
            source = args[-2].split(":", 1)[-1]
            target = Path(args[-1])
            if source in {"/audit/phase", "/audit/qemu-build.log"}:
                target.parent.mkdir(parents=True, exist_ok=True)
                detail = "qemu-build\n" if source == "/audit/phase" else "ninja failed fixture\n"
                target.write_text(detail, encoding="utf-8")
                return subprocess.CompletedProcess(args, 0, stdout="")
            return subprocess.CompletedProcess(args, 1, stdout="not present")
        if args[:2] == ["docker", "logs"]:
            return subprocess.CompletedProcess(args, 0, stdout="")
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(qemu_runtime_build, "run", fake_run)
    inputs = tmp_path / "inputs"
    inputs.mkdir()

    with pytest.raises(qemu_runtime_build.StopBuild, match="qemu-build.log: ninja failed fixture"):
        qemu_runtime_build.run_build_container(
            inputs, tmp_path / "report" / "build-evidence.json", qemu_runtime_build.read_reference()
        )

    assert [args[:2] for args in calls][-1] == ["docker", "rm"]
    assert [args[:2] for args in calls].index(["docker", "logs"]) < len(calls) - 1


def test_container_diagnostics_redact_url_credentials_and_limit_lines(monkeypatch) -> None:
    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args,
            0,
            stdout="\n".join([f"line {index}" for index in range(13)])
            + "\nhttps://user:secret@example.invalid/path\n",
        )

    monkeypatch.setattr(qemu_runtime_build, "run", fake_run)

    diagnostics = qemu_runtime_build.read_container_diagnostics("test-container")

    assert len(diagnostics) == 12
    assert "secret" not in " ".join(diagnostics)
    assert "https://[redacted]@example.invalid/path" in diagnostics[-1]


def test_audit_diagnostics_preserve_package_error_lines_outside_the_log_tail(
    tmp_path: Path,
) -> None:
    audit = tmp_path / "audit"
    audit.mkdir()
    (audit / "apt-install.log").write_text(
        "dpkg: error processing archive package.deb (--unpack): Operation not permitted\n"
        + "\n".join(f"Selecting package {index}" for index in range(24)),
        encoding="utf-8",
    )

    diagnostics = qemu_runtime_build.read_audit_diagnostics(audit)

    assert any("dpkg: error processing archive" in line for line in diagnostics)


def test_build_artifact_validation_requires_qemu_and_all_four_mips_shims() -> None:
    artifacts = [
        {
            "name": "qemu-mipsel",
            "bytes": 1024,
            "sha256": "a" * 64,
            "elf_class": "ELF64",
            "elf_data": "little endian",
            "machine": "Advanced Micro Devices X86-64",
            "flags": "0x0",
            "has_interpreter": False,
        },
        *[
            {
                "name": name,
                "bytes": 128,
                "sha256": "b" * 64,
                "elf_class": "ELF32",
                "elf_data": "little endian",
                "machine": "MIPS R3000",
                "flags": "0x70001407",
                "has_interpreter": False,
            }
            for name in ("fbshim.so", "asndshim.so", "tinyshim.so", "mqshim.so")
        ],
    ]

    qemu_runtime_build.validate_build_artifacts(artifacts)

    with pytest.raises(qemu_runtime_build.StopBuild, match="artifact set"):
        qemu_runtime_build.validate_build_artifacts(artifacts[:-1])

    artifacts[1]["flags"] = "0x0"
    with pytest.raises(qemu_runtime_build.StopBuild, match="shim ABI"):
        qemu_runtime_build.validate_build_artifacts(artifacts)


@pytest.mark.parametrize(
    ("repeat_status", "expected"),
    [
        ("identical", "firmware-free-build-passed-repeat-identical"),
        ("different", "firmware-free-build-passed-repeat-different"),
        ("attempted-failed", "firmware-free-build-passed-repeat-failed"),
        ("not-run", "firmware-free-build-passed-repeat-not-run"),
    ],
)
def test_repeat_status_has_explicit_top_level_build_status(
    repeat_status: str, expected: str
) -> None:
    assert qemu_runtime_build.build_status_for_repeat(repeat_status) == expected


def test_debian_license_inventory_distinguishes_expression_and_full_text() -> None:
    inventory = qemu_runtime_build.debian_license_inventory(
        "Files: named.c\nLicense: GPL-2+\n\n"
        "Files: fulltext.c\nLicense:\n Full license notice.\n .\n Terms.\n"
    )

    assert inventory["license_field_count"] == 2
    assert inventory["license_expressions"] == ["GPL-2+"]
    assert inventory["full_text_license_block_count"] == 1
    assert len(inventory["full_text_license_block_sha256"][0]) == 64
    assert inventory["empty_license_field_count"] == 0
