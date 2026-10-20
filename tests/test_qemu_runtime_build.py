from __future__ import annotations

import importlib.util
import json
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
    assert not any(arg.startswith("--device") for arg in args)
    assert "--privileged" not in args
    assert "-p" not in args
    assert args[-4:] == [
        qemu_runtime_build.BASE_IMAGE,
        "/bin/bash",
        "-euc",
        "set -euo pipefail\ntrue",
    ]


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
    assert "binfmt" not in command
    assert "qemu-user-static" not in command
    assert "qemu-mipsel -version" not in command
    assert "qemu-mipsel-static" not in command


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
