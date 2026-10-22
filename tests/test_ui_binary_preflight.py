"""Synthetic offline acceptance for the M2-02 static comparison boundary."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

import pytest
from test_elf_inspection import _elf32_mips

from snowsky_disc_lab.elf_inspection import ElfInspectionError
from snowsky_disc_lab.ui_binary_preflight import (
    BinaryPathDeclaration,
    BinaryPreflightError,
    preflight_ui_binary,
)


def _fixture(tmp_path: Path, **kwargs: Any) -> tuple[Path, str]:
    raw = _elf32_mips(**kwargs)
    binary = tmp_path / "synthetic-mq-ui"
    binary.write_bytes(raw)
    return binary, hashlib.sha256(raw).hexdigest()


def _paths(digest: str, required: list[str] | None = None) -> dict[str, object]:
    return {
        "apiVersion": "lab-ui-binary-paths/v1",
        "kind": "UIBinaryPaths",
        "binarySha256": digest,
        "requiredPaths": required if required is not None else ["/dev/fb0"],
    }


def _target(digest: str, **changes: object) -> dict[str, object]:
    result: dict[str, object] = {
        "apiVersion": "lab-ui-binary-target/v1",
        "kind": "UIBinaryTarget",
        "binarySha256": digest,
        "runnerId": "synthetic-runner-1",
        "profileId": "synthetic-profile-1",
        "mipsAbi": "O32",
        "floatAbi": "soft",
        "linkage": "dynamic",
        "interpreter": "/lib/ld.so.1",
        "reviewedDependencies": ["libc.so.6"],
        "availablePaths": ["/dev/fb0", "/lib/ld.so.1"],
        "absentPaths": [],
    }
    result.update(changes)
    return result


def test_static_match_is_identity_bound_and_never_authorizes_launch(tmp_path: Path) -> None:
    binary, digest = _fixture(tmp_path, fp_abi=3, load=b"code")
    report = preflight_ui_binary(
        binary,
        target=_target(digest, linkage="static", interpreter=None, reviewedDependencies=[]),
        paths=_paths(digest),
    )

    assert report["status"] == "STATIC_MATCH"
    assert report["reasons"] == []
    assert report["inspection"]["sha256"] == digest
    assert report["inspection"]["sizeBytes"] == binary.stat().st_size
    assert report["inspection"]["neededLibraries"] == []
    assert report["requiredPaths"] == ["/dev/fb0"]
    assert report["launchAuthorized"] is False


def test_missing_target_unknown_abi_and_dependency_evidence_remain_unknown(tmp_path: Path) -> None:
    binary, digest = _fixture(
        tmp_path, dynamic=True, interpreter=b"/lib/ld.so.1", needed=("libc.so.6",)
    )
    report = preflight_ui_binary(binary, paths=_paths(digest))
    assert report["status"] == "UNKNOWN"
    assert "float-abi-unknown" in report["reasons"]
    assert "target-contract-missing" in report["reasons"]

    report = preflight_ui_binary(
        binary, target=_target(digest, reviewedDependencies=[]), paths=_paths(digest)
    )
    assert report["status"] == "UNKNOWN"
    assert "dependencies-unverified" in report["reasons"]

    report = preflight_ui_binary(binary, target=_target(digest), paths=_paths(digest))
    assert report["status"] == "UNKNOWN"
    assert "dependencies-unverified" in report["reasons"]


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"machine": 62}, "machine-mismatch"),
        ({"file_type": 1, "fp_abi": 3}, "file-type-mismatch"),
        ({"flags": 0x2000, "fp_abi": 3}, "mips-abi-mismatch"),
        ({"fp_abi": 1}, "target-float-mismatch"),
    ],
)
def test_known_incompatibilities_block(tmp_path: Path, kwargs: dict[str, Any], reason: str) -> None:
    binary, digest = _fixture(tmp_path, **kwargs)
    report = preflight_ui_binary(binary, target=_target(digest), paths=_paths(digest))
    assert report["status"] == "BLOCKED"
    assert reason in report["reasons"]


def test_unknown_linkage_and_abi_never_become_static_match(tmp_path: Path) -> None:
    binary, digest = _fixture(tmp_path, fp_abi=0, flags=0)
    report = preflight_ui_binary(
        binary,
        target=_target(digest, linkage="static", interpreter=None, reviewedDependencies=[]),
        paths=_paths(digest),
    )
    assert report["status"] == "UNKNOWN"
    assert {"mips-abi-unknown", "float-abi-unknown", "linkage-unknown"} <= set(report["reasons"])


def test_required_paths_only_come_from_exact_identity_review(tmp_path: Path) -> None:
    binary, digest = _fixture(tmp_path, fp_abi=3, load=b"/secret/elf-string\x00")
    target = _target(digest, linkage="static", interpreter=None, reviewedDependencies=[])
    report = preflight_ui_binary(binary, target=target)
    assert report["requiredPaths"] == []
    assert report["status"] == "UNKNOWN"
    assert "required-paths-unreviewed" in report["reasons"]
    assert "/secret/elf-string" not in str(report)

    report = preflight_ui_binary(binary, target=target, paths=_paths("0" * 64))
    assert report["status"] == "BLOCKED"
    assert report["requiredPaths"] == []


def test_target_path_presence_and_known_absence(tmp_path: Path) -> None:
    binary, digest = _fixture(tmp_path, fp_abi=3, load=b"code")
    target = _target(
        digest, linkage="static", interpreter=None, reviewedDependencies=[], availablePaths=[]
    )
    report = preflight_ui_binary(binary, target=target, paths=_paths(digest))
    assert report["status"] == "UNKNOWN"
    assert "required-path-unverified" in report["reasons"]

    target["absentPaths"] = ["/dev/fb0"]
    report = preflight_ui_binary(binary, target=target, paths=_paths(digest))
    assert report["status"] == "BLOCKED"
    assert "required-path-known-absent" in report["reasons"]


def test_interpreter_absence_and_other_unknowns_are_both_reported(tmp_path: Path) -> None:
    binary, digest = _fixture(
        tmp_path, dynamic=True, interpreter=b"/lib/ld.so.1", needed=("libc.so.6",), fp_abi=3
    )
    target = _target(
        digest,
        availablePaths=["/dev/fb0"],
        absentPaths=["/lib/ld.so.1"],
    )
    report = preflight_ui_binary(binary, target=target, paths=_paths(digest))
    assert report["status"] == "BLOCKED"
    assert {"interpreter-known-absent", "dependencies-unverified"} <= set(report["reasons"])


def test_elf64_is_blocked_by_binary_policy(tmp_path: Path) -> None:
    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8)
    binary = tmp_path / "synthetic-elf64"
    binary.write_bytes(
        struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 8, 1, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0)
    )
    report = preflight_ui_binary(binary)
    assert report["status"] == "BLOCKED"
    assert "elf-class-mismatch" in report["reasons"]


def test_big_endian_mips_is_blocked_by_binary_policy(tmp_path: Path) -> None:
    ident = b"\x7fELF" + bytes((1, 2, 1, 0)) + bytes(8)
    binary = tmp_path / "synthetic-big-endian"
    binary.write_bytes(
        struct.pack(">16sHHIIIIIHHHHHH", ident, 2, 8, 1, 0, 0, 0, 0x1000, 52, 0, 0, 0, 0, 0)
    )
    report = preflight_ui_binary(binary)
    assert report["status"] == "BLOCKED"
    assert "endianness-mismatch" in report["reasons"]


def test_rejects_malformed_contracts_and_revalidates_mutated_models(tmp_path: Path) -> None:
    binary, digest = _fixture(tmp_path, fp_abi=3, load=b"code")
    target = _target(digest, linkage="static", interpreter=None, reviewedDependencies=[])
    with pytest.raises(BinaryPreflightError, match="requiredPaths"):
        preflight_ui_binary(binary, target=target, paths=_paths(digest, ["/dev/../unsafe"]))
    with pytest.raises(BinaryPreflightError, match="inventory"):
        preflight_ui_binary(binary, target={**target, "availablePaths": ["/dev/fb0", "/dev/fb0"]})
    declaration = BinaryPathDeclaration.model_validate(_paths(digest))
    declaration.requiredPaths.append("/../unsafe")
    with pytest.raises(BinaryPreflightError, match="requiredPaths"):
        preflight_ui_binary(binary, target=target, paths=declaration)

    copied = BinaryPathDeclaration.model_validate(_paths(digest)).model_copy(
        update={"binarySha256": "not-a-digest"}
    )
    with pytest.raises(BinaryPreflightError, match="binarySha256"):
        preflight_ui_binary(binary, target=target, paths=copied)

    with pytest.raises(BinaryPreflightError, match="apiVersion"):
        preflight_ui_binary(binary, target={**target, "apiVersion": "future"})
    with pytest.raises(BinaryPreflightError, match="contract"):
        preflight_ui_binary(binary, target={**target, "unexpected": True})


def test_target_identity_mismatch_blocks(tmp_path: Path) -> None:
    binary, digest = _fixture(tmp_path, fp_abi=3, load=b"code")
    report = preflight_ui_binary(binary, target=_target("0" * 64), paths=_paths(digest))
    assert report["status"] == "BLOCKED"
    assert "target-binary-identity-mismatch" in report["reasons"]


def test_existing_elf_bounds_and_parse_refusal_apply(tmp_path: Path) -> None:
    binary, _ = _fixture(tmp_path, fp_abi=3)
    with pytest.raises(ElfInspectionError, match="size limit"):
        preflight_ui_binary(binary, max_bytes=16)
