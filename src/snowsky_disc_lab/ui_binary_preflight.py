"""Offline, identity-bound static checks for an externally supplied UI ELF.

Inputs describing the target are caller-supplied reviewed declarations, not
authenticated runtime observations. This module never grants launch authority.
"""

from __future__ import annotations

import os
from typing import Annotated, Literal, TypedDict

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from snowsky_disc_lab.elf_inspection import ElfInspection, inspect_elf

Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$", strict=True)]
Identifier = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", strict=True)
]
GuestPath = Annotated[str, StringConstraints(min_length=2, max_length=256, strict=True)]
LibraryName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_+.-]{1,128}$", strict=True)]


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class BinaryPathDeclaration(_Contract):
    """Reviewed path claims tied to the exact selected binary bytes."""

    apiVersion: Literal["lab-ui-binary-paths/v1"]
    kind: Literal["UIBinaryPaths"]
    binarySha256: Sha256
    requiredPaths: Annotated[list[GuestPath], Field(max_length=128)]


class BinaryTarget(_Contract):
    """Explicit target snapshot; its assertions require independent review."""

    apiVersion: Literal["lab-ui-binary-target/v1"]
    kind: Literal["UIBinaryTarget"]
    binarySha256: Sha256
    runnerId: Identifier
    profileId: Identifier
    mipsAbi: Literal["O32"]
    floatAbi: Literal["soft", "hard"]
    linkage: Literal["static", "dynamic"]
    interpreter: GuestPath | None
    reviewedDependencies: Annotated[list[LibraryName], Field(max_length=256)]
    availablePaths: Annotated[list[GuestPath], Field(max_length=256)]
    absentPaths: Annotated[list[GuestPath], Field(max_length=256)]


class BinaryPreflightError(ValueError):
    """Sanitized contract refusal; inspected values are never echoed."""


class InspectionReport(TypedDict):
    fileName: str
    sizeBytes: int
    sha256: str
    elfClass: str
    endianness: str
    machine: str
    fileType: str
    mipsAbi: str
    floatAbi: str
    linkage: str
    interpreter: str | None
    neededLibraries: list[str]


class BinaryPreflightReport(TypedDict):
    apiVersion: str
    kind: str
    status: str
    reasons: list[str]
    inspection: InspectionReport
    requiredPaths: list[str]
    runnerId: str | None
    profileId: str | None
    launchAuthorized: bool


def _guest_path(value: str) -> bool:
    return (
        value.startswith("/")
        and not value.startswith("//")
        and "\\" not in value
        and "\x00" not in value
        and all(part not in {"", ".", ".."} for part in value[1:].split("/"))
        and all(32 <= ord(character) < 127 for character in value)
    )


def _parse[T: _Contract](model: type[T], data: object) -> T:
    # Frozen Pydantic models may still contain mutable lists or model_copy updates.
    if isinstance(data, model):
        data = data.model_dump(warnings="none")
    try:
        parsed = model.model_validate(data)
    except ValidationError as error:
        location = error.errors(include_url=False, include_context=False, include_input=False)[0][
            "loc"
        ]
        field = location[0] if location and isinstance(location[0], str) else "contract"
        if field not in model.model_fields:
            field = "contract"
        raise BinaryPreflightError(f"invalid {model.__name__}: {field}") from None
    if isinstance(parsed, BinaryPathDeclaration):
        paths = parsed.requiredPaths
        if any(not _guest_path(path) for path in paths) or len(set(paths)) != len(paths):
            raise BinaryPreflightError("invalid BinaryPathDeclaration: requiredPaths")
    elif isinstance(parsed, BinaryTarget):
        if not parsed.runnerId or not parsed.profileId:
            raise BinaryPreflightError("invalid BinaryTarget: runnerId/profileId")
        if any(not _guest_path(path) for path in parsed.availablePaths + parsed.absentPaths):
            raise BinaryPreflightError("invalid BinaryTarget: paths")
        if parsed.interpreter is not None and not _guest_path(parsed.interpreter):
            raise BinaryPreflightError("invalid BinaryTarget: interpreter")
        if any(
            len(set(items)) != len(items)
            for items in (parsed.reviewedDependencies, parsed.availablePaths, parsed.absentPaths)
        ) or set(parsed.availablePaths) & set(parsed.absentPaths):
            raise BinaryPreflightError("invalid BinaryTarget: inventory")
    return parsed


def _inspection_dict(elf: ElfInspection) -> InspectionReport:
    return {
        "fileName": elf.file_name,
        "sizeBytes": elf.size_bytes,
        "sha256": elf.sha256,
        "elfClass": elf.elf_class,
        "endianness": elf.endianness,
        "machine": elf.machine,
        "fileType": elf.file_type,
        "mipsAbi": elf.mips_abi,
        "floatAbi": elf.float_abi,
        "linkage": elf.static_dynamic,
        "interpreter": elf.interpreter,
        "neededLibraries": list(elf.needed_libraries),
    }


def preflight_ui_binary(
    path: str | os.PathLike[str],
    *,
    target: object = None,
    paths: object = None,
    max_bytes: int = 128 * 1024 * 1024,
) -> BinaryPreflightReport:
    """Compare bounded ELF metadata with explicit reviewed declarations.

    STATIC_MATCH means only that the supplied static assertions line up. It is
    not compatibility evidence or permission to execute the binary.
    """
    elf = inspect_elf(path, max_bytes=max_bytes)
    target_data = _parse(BinaryTarget, target) if target is not None else None
    path_data = _parse(BinaryPathDeclaration, paths) if paths is not None else None
    blocked: list[str] = []
    unknown: list[str] = []

    if elf.elf_class != "ELF32":
        blocked.append("elf-class-mismatch")
    if elf.endianness != "little":
        blocked.append("endianness-mismatch")
    if elf.machine_id != 8:
        blocked.append("machine-mismatch")
    if elf.file_type != "executable":
        blocked.append("file-type-mismatch")
    if elf.mips_abi == "UNKNOWN":
        unknown.append("mips-abi-unknown")
    elif elf.mips_abi != "O32":
        blocked.append("mips-abi-mismatch")
    if elf.float_abi == "UNKNOWN":
        unknown.append("float-abi-unknown")
    if elf.static_dynamic == "UNKNOWN":
        unknown.append("linkage-unknown")

    required_paths: list[str] = []
    if path_data is None:
        unknown.append("required-paths-unreviewed")
    elif path_data.binarySha256 != elf.sha256:
        blocked.append("path-declaration-identity-mismatch")
    else:
        required_paths = list(path_data.requiredPaths)

    if target_data is None:
        unknown.append("target-contract-missing")
    elif target_data.binarySha256 != elf.sha256:
        blocked.append("target-binary-identity-mismatch")
    else:
        if elf.mips_abi != "UNKNOWN" and elf.mips_abi != target_data.mipsAbi:
            blocked.append("target-abi-mismatch")
        if elf.float_abi != "UNKNOWN" and elf.float_abi != target_data.floatAbi:
            blocked.append("target-float-mismatch")
        if elf.static_dynamic != "UNKNOWN" and elf.static_dynamic != target_data.linkage:
            blocked.append("target-linkage-mismatch")
        if elf.interpreter != target_data.interpreter:
            blocked.append("target-interpreter-mismatch")
        # Names in a reviewed contract do not establish the identity or bytes
        # of libraries in a target rootfs. Keep dynamic dependency evidence open.
        if elf.needed_libraries:
            unknown.append("dependencies-unverified")
        if elf.interpreter is not None:
            if elf.interpreter in target_data.absentPaths:
                blocked.append("interpreter-known-absent")
            elif elf.interpreter not in target_data.availablePaths:
                unknown.append("interpreter-unverified")
        absent = set(required_paths) & set(target_data.absentPaths)
        if absent:
            blocked.append("required-path-known-absent")
        elif set(required_paths) - set(target_data.availablePaths):
            unknown.append("required-path-unverified")

    status = "BLOCKED" if blocked else "UNKNOWN" if unknown else "STATIC_MATCH"
    return {
        "apiVersion": "lab-ui-binary-preflight/v1",
        "kind": "UIBinaryPreflight",
        "status": status,
        "reasons": sorted(set(blocked + unknown)),
        "inspection": _inspection_dict(elf),
        "requiredPaths": required_paths,
        "runnerId": target_data.runnerId if target_data else None,
        "profileId": target_data.profileId if target_data else None,
        "launchAuthorized": False,
    }
