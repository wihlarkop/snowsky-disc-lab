"""Strict, firmware-free source/build-plan validation for external UIs.

This module records declarations and inspects source/output bytes. It never
executes a build recipe or authorizes an UI launch.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from datetime import date
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from snowsky_disc_lab.source_lock import SourcePin, load_source_lock
from snowsky_disc_lab.sources import SourceError, verify_source
from snowsky_disc_lab.ui_binary_preflight import preflight_ui_binary

_REPOSITORY = re.compile(
    r"^https://github\.com/[A-Za-z0-9][A-Za-z0-9-]*/"
    r"[A-Za-z0-9][A-Za-z0-9._-]*\.git$"
)
_COMMIT = r"^[0-9a-f]{40}$"
_SHA256 = r"^[0-9a-f]{64}$"
_MAX_FILES = 10_000
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 512 * 1024 * 1024
_MAX_SCAN_SECONDS = 15

SourceId = Annotated[str, StringConstraints(strict=True, pattern=r"^[a-z][a-z0-9-]{0,47}$")]
SafePath = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=512)]
Sha256 = Annotated[str, StringConstraints(strict=True, pattern=_SHA256)]
Reference = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=256)]


class _Contract(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, validate_by_alias=True, validate_by_name=False
    )


class SourceProvenance(_Contract):
    reference: Reference
    reviewed_on: Annotated[str, StringConstraints(strict=True, pattern=r"^\d{4}-\d{2}-\d{2}$")] = (
        Field(alias="reviewedOn")
    )

    @field_validator("reviewed_on")
    @classmethod
    def valid_review_date(cls, value: str) -> str:
        try:
            date.fromisoformat(value)
        except ValueError:
            raise ValueError("review date must be a calendar date") from None
        return value


class LocalSource(_Contract):
    mode: Literal["local"]
    source_id: SourceId = Field(alias="sourceId")
    provenance: SourceProvenance
    projection: Annotated[list[SafePath], Field(min_length=1, max_length=128)]
    manifest_sha256: Sha256 = Field(alias="manifestSha256")


class GitSource(_Contract):
    mode: Literal["git"]
    source_id: SourceId = Field(alias="sourceId")
    repository: Annotated[str, StringConstraints(strict=True, max_length=256)]
    commit: Annotated[str, StringConstraints(strict=True, pattern=_COMMIT)]
    provenance: SourceProvenance
    manifest_sha256: Sha256 = Field(alias="manifestSha256")


class BuildRecipe(_Contract):
    recipe_id: Annotated[str, StringConstraints(strict=True, pattern=r"^[a-z][a-z0-9-]{0,47}$")] = (
        Field(alias="recipeId")
    )
    revision: Annotated[str, StringConstraints(strict=True, pattern=_COMMIT)]
    review_reference: Reference = Field(alias="reviewReference")
    review_status: Literal["reviewed", "unreviewed"] = Field(alias="reviewStatus")


class BuildInput(_Contract):
    name: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=64)]
    version: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=64)]
    sha256: Sha256


class ExpectedOutput(_Contract):
    path: SafePath
    sha256: Sha256


class SourceModePlan(_Contract):
    api_version: Literal["lab-ui-source-mode/v1"] = Field(alias="apiVersion")
    kind: Literal["UISourceModePlan"]
    source: LocalSource | GitSource = Field(discriminator="mode")
    recipe: BuildRecipe
    inputs: Annotated[list[BuildInput], Field(min_length=1, max_length=64)]
    output: ExpectedOutput


class BuildRecord(_Contract):
    api_version: Literal["lab-ui-build-record/v1"] = Field(alias="apiVersion")
    kind: Literal["UIBuildRecord"]
    plan_sha256: Sha256 = Field(alias="planSha256")
    source_manifest_sha256: Sha256 = Field(alias="sourceManifestSha256")
    recipe_revision: Annotated[str, StringConstraints(strict=True, pattern=_COMMIT)] = Field(
        alias="recipeRevision"
    )
    output_sha256: Sha256 = Field(alias="outputSha256")
    execution: Literal["NOT RUN"]
    reproducibility: Literal["NOT MEASURED"]
    authentication: Literal["NOT RUN"]
    launch_authorized: Literal[False] = Field(alias="launchAuthorized")

    @model_validator(mode="before")
    @classmethod
    def strict_launch_authority(cls, data: object) -> object:
        _require_false_authority(data)
        return data


class LocalSourceEvidence(_Contract):
    mode: Literal["local"]
    source_id: SourceId = Field(alias="sourceId")
    provenance_reference: Reference = Field(alias="provenanceReference")
    reviewed_on: Annotated[str, StringConstraints(strict=True, pattern=r"^\d{4}-\d{2}-\d{2}$")] = (
        Field(alias="reviewedOn")
    )

    @field_validator("reviewed_on")
    @classmethod
    def valid_review_date(cls, value: str) -> str:
        try:
            date.fromisoformat(value)
        except ValueError:
            raise ValueError("review date must be a calendar date") from None
        return value

    status: Literal["INSPECTED"]
    manifest_sha256: Sha256 = Field(alias="manifestSha256")


class GitSourceEvidence(_Contract):
    mode: Literal["git"]
    source_id: SourceId = Field(alias="sourceId")
    provenance_reference: Reference = Field(alias="provenanceReference")
    reviewed_on: Annotated[str, StringConstraints(strict=True, pattern=r"^\d{4}-\d{2}-\d{2}$")] = (
        Field(alias="reviewedOn")
    )
    repository: str
    commit: Annotated[str, StringConstraints(strict=True, pattern=_COMMIT)]
    projection: list[SafePath]
    status: Literal["VERIFIED_CACHE"]
    manifest_sha256: Sha256 = Field(alias="manifestSha256")


class ProjectionEvidence(_Contract):
    file_count: Annotated[int, Field(strict=True, ge=0, le=_MAX_FILES)] = Field(alias="fileCount")
    total_bytes: Annotated[int, Field(strict=True, ge=0, le=_MAX_TOTAL_BYTES)] = Field(
        alias="totalBytes"
    )


class RecipeEvidence(_Contract):
    recipe_id: str = Field(alias="recipeId")
    revision: Annotated[str, StringConstraints(strict=True, pattern=_COMMIT)]
    review_reference: Reference = Field(alias="reviewReference")
    review_status: Literal["DECLARED_REVIEWED"] = Field(alias="reviewStatus")


class OutputEvidence(_Contract):
    path: SafePath
    declared_sha256: Sha256 = Field(alias="declaredSha256")
    inspected_sha256: Sha256 | None = Field(alias="inspectedSha256")
    preflight_status: Literal["NOT RUN", "BLOCKED", "UNKNOWN", "STATIC_MATCH"] = Field(
        alias="preflightStatus"
    )
    launch_authorized: Literal[False] = Field(alias="launchAuthorized")

    @model_validator(mode="before")
    @classmethod
    def strict_launch_authority(cls, data: object) -> object:
        _require_false_authority(data)
        return data


class SourceModeEvidence(_Contract):
    source_bytes: Literal["INSPECTED"] = Field(alias="sourceBytes")
    git_commit_binding: Literal["VERIFIED", "NOT APPLICABLE"] = Field(alias="gitCommitBinding")
    authentication: Literal["NOT RUN"]
    build_execution: Literal["NOT RUN"] = Field(alias="buildExecution")
    reproducibility: Literal["NOT MEASURED"]
    launch_authorized: Literal[False] = Field(alias="launchAuthorized")

    @model_validator(mode="before")
    @classmethod
    def strict_launch_authority(cls, data: object) -> object:
        _require_false_authority(data)
        return data


class SourceModeReport(_Contract):
    api_version: Literal["lab-ui-source-mode-report/v1"] = Field(alias="apiVersion")
    kind: Literal["UISourceModeReport"]
    plan_sha256: Sha256 = Field(alias="planSha256")
    status: Literal["VALIDATED"]
    source: LocalSourceEvidence | GitSourceEvidence = Field(discriminator="mode")
    projection: ProjectionEvidence
    recipe: RecipeEvidence
    output: OutputEvidence
    inputs: Annotated[list[BuildInput], Field(min_length=1, max_length=64)]
    evidence: SourceModeEvidence


class SourceModeError(ValueError):
    """Sanitized validation or source inspection refusal."""


def _safe_error_fields(model: type[BaseModel], error: ValidationError) -> list[str]:
    fields = set(model.model_fields)
    fields.update(field.alias for field in model.model_fields.values() if field.alias is not None)
    result = {
        str(issue["loc"][0])
        if issue["loc"] and isinstance(issue["loc"][0], str) and issue["loc"][0] in fields
        else "contract"
        for issue in error.errors(include_url=False, include_context=False, include_input=False)[:8]
    }
    return sorted(result)


def _require_false_authority(data: object) -> None:
    if isinstance(data, dict) and "launchAuthorized" in data:
        value = data["launchAuthorized"]
        if type(value) is not bool or value is not False:
            raise ValueError("launchAuthorized must be the boolean false")


def _parse(data: object) -> SourceModePlan:
    if isinstance(data, SourceModePlan):
        data = data.model_dump(by_alias=True, warnings="none")
    try:
        plan = SourceModePlan.model_validate(data)
    except ValidationError as error:
        raise SourceModeError(
            "Invalid UI source mode contract: "
            + ", ".join(_safe_error_fields(SourceModePlan, error))
        ) from None
    _validate_plan_paths(plan)
    if plan.recipe.review_status != "reviewed":
        raise SourceModeError("Build recipe must have an explicitly reviewed identity.")
    if len({item.name for item in plan.inputs}) != len(plan.inputs):
        raise SourceModeError("Build input names must be unique.")
    return plan


def _plan_identity(plan: SourceModePlan) -> str:
    canonical = json.dumps(
        plan.model_dump(by_alias=True, mode="json", warnings="none"),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def source_mode_plan_sha256(data: object) -> str:
    """Return the canonical identity used to bind build records to a full plan."""
    return _plan_identity(_parse(data))


def _validate_projection(projection: object) -> list[str]:
    if (
        not isinstance(projection, list)
        or not 1 <= len(projection) <= 128
        or any(not isinstance(path, str) for path in projection)
    ):
        raise SourceModeError("Source projection must contain 1 to 128 path strings.")
    paths = [path[:-1] if path.endswith("/") else path for path in projection]
    parsed = [_safe_relative(path) for path in paths]
    normalized = [path.as_posix() for path in parsed]
    if len(set(normalized)) != len(normalized):
        raise SourceModeError("Source projection paths must be unique.")
    for left in parsed:
        if any(left != right and left in right.parents for right in parsed):
            raise SourceModeError("Source projection paths must not overlap.")
    return projection


def _safe_relative(value: str) -> PurePosixPath:
    windows = PureWindowsPath(value)
    path = PurePosixPath(value)
    if (
        "\\" in value
        or ":" in value
        or value.startswith("/")
        or windows.drive
        or windows.is_absolute()
        or path.is_absolute()
        or tuple(path.parts) != tuple(value.split("/"))
        or any(part in {"", ".", "..", ".git"} for part in path.parts)
        or any(not _portable_component(part) for part in path.parts)
    ):
        raise SourceModeError("Source and output paths must be safe relative POSIX paths.")
    return path


def _portable_component(part: str) -> bool:
    if (
        part.casefold() == ".git"
        or part.endswith((".", " "))
        or any(char in '<>:"|?*\\/' for char in part)
        or any(ord(char) < 32 or ord(char) == 127 for char in part)
    ):
        return False
    stem = part.partition(".")[0].upper()
    if stem in {"CON", "PRN", "AUX", "NUL"}:
        return False
    return re.fullmatch(r"(?:COM|LPT)[1-9]", stem) is None


def _validate_plan_paths(plan: SourceModePlan) -> None:
    output = _safe_relative(plan.output.path)
    if plan.source.mode == "local":
        paths = [
            _safe_relative(value[:-1] if value.endswith("/") else value)
            for value in _validate_projection(plan.source.projection)
        ]
        if any(
            output == path or output in path.parents or path in output.parents for path in paths
        ):
            raise SourceModeError("Expected output path must be outside the source projection.")
    else:
        if not _REPOSITORY.fullmatch(plan.source.repository):
            raise SourceModeError("Git source must use a canonical HTTPS GitHub repository URL.")


def _reparse(entry: os.stat_result) -> bool:
    return stat.S_ISLNK(entry.st_mode) or bool(
        getattr(entry, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _checked_root(path: Path) -> Path:
    raw = os.fspath(path)
    windows = PureWindowsPath(raw)
    if (
        raw.startswith(("\\\\", "//"))
        or any(part == ".." for part in Path(raw).parts)
        or any(":" in part for part in windows.parts[1:])
        or (windows.drive and not windows.is_absolute())
    ):
        raise SourceModeError("Selected source root cannot use a UNC, device, or traversal path.")
    selected = Path(os.path.abspath(raw))
    components = list(reversed((selected, *selected.parents)))
    for component in components:
        if component.name.casefold() == ".git":
            raise SourceModeError("Selected source root cannot be inside Git metadata.")
        try:
            entry = component.lstat()
        except OSError:
            raise SourceModeError(
                "Selected source root is missing or cannot be inspected safely."
            ) from None
        if _reparse(entry):
            raise SourceModeError("Selected source path contains a symlink or junction.")
    if not selected.is_dir():
        raise SourceModeError("Selected source root must be a directory.")
    return selected


def _projection_entries(root: Path, selections: list[str]) -> list[tuple[str, Path]]:
    selected: dict[str, Path] = {}
    started = time.monotonic()
    for item in selections:
        normalized = item[:-1] if item.endswith("/") else item
        relative = _safe_relative(normalized)
        candidate = root
        final = root.joinpath(*relative.parts)
        info: os.stat_result | None = None
        for part in relative.parts:
            candidate = candidate / part
            try:
                info = candidate.lstat()
            except OSError:
                raise SourceModeError("A declared source projection path is missing.") from None
            if _reparse(info):
                raise SourceModeError("Source projection contains a symlink or junction.")
            if candidate != final and not stat.S_ISDIR(info.st_mode):
                raise SourceModeError("Source projection traverses a non-directory entry.")
        assert info is not None
        if item.endswith("/") and not stat.S_ISDIR(info.st_mode):
            raise SourceModeError("Pinned source directory projection is not a directory.")
        if stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise SourceModeError("Source projection contains a hard-linked file.")
            selected[relative.as_posix()] = candidate
        elif stat.S_ISDIR(info.st_mode):
            for directory, child_dirs, files in os.walk(
                candidate, topdown=True, followlinks=False, onerror=_walk_error
            ):
                if time.monotonic() - started > _MAX_SCAN_SECONDS:
                    raise SourceModeError("Source inspection exceeded its time limit.")
                base = Path(directory)
                for name in list(child_dirs):
                    if not _portable_component(name):
                        raise SourceModeError(
                            "Source projection contains a non-portable path name."
                        )
                    child = base / name
                    metadata = child.lstat()
                    if _reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
                        raise SourceModeError(
                            "Source projection contains an unsafe directory entry."
                        )
                    if name.casefold() == ".git":
                        raise SourceModeError(
                            "Local source projection cannot include Git metadata."
                        )
                for name in files:
                    if not _portable_component(name):
                        raise SourceModeError(
                            "Source projection contains a non-portable path name."
                        )
                    file_path = base / name
                    metadata = file_path.lstat()
                    if (
                        _reparse(metadata)
                        or not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_nlink != 1
                    ):
                        raise SourceModeError("Source projection contains a link or special file.")
                    rel = file_path.relative_to(root).as_posix()
                    selected[rel] = file_path
                    if len(selected) > _MAX_FILES:
                        raise SourceModeError("Source projection exceeds the file-count limit.")
        else:
            raise SourceModeError("Source projection entries must be regular files or directories.")
    return sorted(selected.items())


def _manifest(root: Path, selections: list[str]) -> tuple[str, int, int]:
    _validate_projection(selections)
    entries = _projection_entries(root, selections)
    if len(entries) > _MAX_FILES:
        raise SourceModeError("Source projection exceeds the file-count limit.")
    total = 0
    portable_paths: set[str] = set()
    manifest_entries: list[dict[str, object]] = []
    started = time.monotonic()
    for rel, path in entries:
        folded = rel.casefold()
        if folded in portable_paths:
            raise SourceModeError(
                "Source projection has paths that collide on portable filesystems."
            )
        portable_paths.add(folded)
        before = path.lstat()
        if _reparse(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise SourceModeError("Source projection contains a link or special file.")
        if before.st_size > _MAX_FILE_BYTES:
            raise SourceModeError("A source file exceeds the per-file inspection limit.")
        total += before.st_size
        if total > _MAX_TOTAL_BYTES:
            raise SourceModeError("Source projection exceeds the total byte limit.")
        digest = hashlib.sha256()
        actual_size = 0
        try:
            with path.open("rb") as stream:
                while block := stream.read(1024 * 1024):
                    actual_size += len(block)
                    if (
                        actual_size > _MAX_FILE_BYTES
                        or total - before.st_size + actual_size > _MAX_TOTAL_BYTES
                    ):
                        raise SourceModeError(
                            "Source projection grew beyond its byte limit during inspection."
                        )
                    digest.update(block)
                    if time.monotonic() - started > _MAX_SCAN_SECONDS:
                        raise SourceModeError("Source inspection exceeded its time limit.")
        except OSError:
            raise SourceModeError("A source file is missing or unreadable.") from None
        after = path.lstat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise SourceModeError("A source file changed during inspection.")
        if actual_size != before.st_size:
            raise SourceModeError("A source file changed size during inspection.")
        manifest_entries.append(
            {"path": rel, "sha256": digest.hexdigest(), "sizeBytes": before.st_size}
        )
    canonical = json.dumps(
        manifest_entries, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest(), len(entries), total


def inspect_local_projection(root: Path, projection: list[str]) -> dict[str, object]:
    """Measure a bounded local source projection for use in a reviewed plan."""
    checked = _checked_root(root)
    identity, file_count, total_bytes = _manifest(checked, _validate_projection(projection))
    return {
        "status": "INSPECTED",
        "manifestSha256": identity,
        "fileCount": file_count,
        "totalBytes": total_bytes,
    }


def _pin_for(plan: GitSource, lock_path: Path) -> SourcePin:
    try:
        lock = load_source_lock(lock_path)
    except (OSError, ValueError):
        raise SourceModeError("The selected source lock is invalid or unavailable.") from None
    matches = [pin for pin in lock.sources if pin.id == plan.source_id]
    if len(matches) != 1:
        raise SourceModeError("Git source ID does not resolve to exactly one locked source.")
    pin = matches[0]
    if pin.repository != plan.repository or pin.commit != plan.commit:
        raise SourceModeError("Git source identity differs from the reviewed source lock.")
    if (
        plan.provenance.reference != pin.provenance.reference
        or plan.provenance.reviewed_on != pin.provenance.reviewed_on
    ):
        raise SourceModeError("Git provenance differs from the reviewed source lock.")
    return pin


def _walk_error(_error: OSError) -> None:
    raise SourceModeError("Source projection contains an unreadable directory.") from None


def _output_file(root: Path, relative: str) -> Path:
    output = root.joinpath(*_safe_relative(relative).parts)
    current = root
    for part in _safe_relative(relative).parts:
        current = current / part
        try:
            entry = current.lstat()
        except OSError:
            raise SourceModeError("Expected output ELF is missing.") from None
        if _reparse(entry):
            raise SourceModeError("Expected output path contains a symlink or junction.")
        if current != output and not stat.S_ISDIR(entry.st_mode):
            raise SourceModeError("Expected output path traverses a non-directory entry.")
    try:
        entry = output.lstat()
    except OSError:
        raise SourceModeError("Expected output ELF is missing.") from None
    if not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1:
        raise SourceModeError("Expected output must be a regular file without links.")
    return output


def inspect_source_mode(
    data: object,
    *,
    local_root: Path | None = None,
    lock_path: Path | None = None,
    cache_root: Path | None = None,
    build_root: Path | None = None,
    binary_target: object = None,
    binary_paths: object = None,
) -> dict[str, Any]:
    """Validate plan identity, inspect source/output bytes, and report execution boundaries.

    Git mode is offline and requires an exact matching source lock and verified cache.
    Local mode reads only the declared projection. Recipe execution is never attempted.
    """
    plan = _parse(data)
    if plan.source.mode == "local":
        if local_root is None:
            raise SourceModeError("Local source mode requires an explicitly selected directory.")
        root = _checked_root(local_root)
        manifest_sha, file_count, total_bytes = _manifest(root, plan.source.projection)
        if manifest_sha != plan.source.manifest_sha256:
            raise SourceModeError(
                "Local source projection differs from its declared manifest identity."
            )
        source_status = "INSPECTED"
        source_identity: dict[str, object] = {
            "sourceId": plan.source.source_id,
            "provenanceReference": plan.source.provenance.reference,
            "reviewedOn": plan.source.provenance.reviewed_on,
        }
    else:
        if lock_path is None or cache_root is None:
            raise SourceModeError("Pinned Git mode requires the source lock and cache directory.")
        pin = _pin_for(plan.source, lock_path)
        try:
            root = verify_source(pin, cache_root)
        except (SourceError, OSError):
            raise SourceModeError("Pinned Git source cache failed offline verification.") from None
        manifest_sha, file_count, total_bytes = _manifest(root, pin.include_paths)
        if manifest_sha != plan.source.manifest_sha256:
            raise SourceModeError(
                "Verified Git projection differs from its declared manifest identity."
            )
        source_status = "VERIFIED_CACHE"
        source_identity = {
            "sourceId": pin.id,
            "provenanceReference": pin.provenance.reference,
            "reviewedOn": pin.provenance.reviewed_on,
            "repository": pin.repository,
            "commit": pin.commit,
            "projection": sorted(pin.include_paths),
        }

    output_sha: str | None = None
    output_status = "NOT RUN"
    if build_root is not None:
        output_root = _checked_root(build_root)
        output_path = _output_file(output_root, plan.output.path)
        metadata_before = output_path.lstat()
        try:
            inspected = preflight_ui_binary(output_path, target=binary_target, paths=binary_paths)
        except ValueError as error:
            raise SourceModeError(f"Expected output ELF could not be inspected: {error}") from None
        actual_sha = inspected["inspection"]["sha256"]
        metadata_after = output_path.lstat()
        if (
            metadata_before.st_dev,
            metadata_before.st_ino,
            metadata_before.st_size,
            metadata_before.st_mtime_ns,
        ) != (
            metadata_after.st_dev,
            metadata_after.st_ino,
            metadata_after.st_size,
            metadata_after.st_mtime_ns,
        ):
            raise SourceModeError("Expected output ELF changed during inspection.")
        if actual_sha != plan.output.sha256:
            raise SourceModeError("Expected output ELF digest does not match the inspected bytes.")
        output_sha = actual_sha
        output_status = inspected["status"]

    result = {
        "apiVersion": "lab-ui-source-mode-report/v1",
        "kind": "UISourceModeReport",
        "planSha256": _plan_identity(plan),
        "status": "VALIDATED",
        "source": {
            **source_identity,
            "mode": plan.source.mode,
            "status": source_status,
            "manifestSha256": manifest_sha,
        },
        "projection": {"fileCount": file_count, "totalBytes": total_bytes},
        "recipe": {
            "recipeId": plan.recipe.recipe_id,
            "revision": plan.recipe.revision,
            "reviewReference": plan.recipe.review_reference,
            "reviewStatus": "DECLARED_REVIEWED",
        },
        "output": {
            "path": plan.output.path,
            "declaredSha256": plan.output.sha256,
            "inspectedSha256": output_sha,
            "preflightStatus": output_status,
            "launchAuthorized": False,
        },
        "inputs": [item.model_dump(by_alias=True, warnings="none") for item in plan.inputs],
        "evidence": {
            "sourceBytes": "INSPECTED",
            "gitCommitBinding": "VERIFIED" if plan.source.mode == "git" else "NOT APPLICABLE",
            "authentication": "NOT RUN",
            "buildExecution": "NOT RUN",
            "reproducibility": "NOT MEASURED",
            "launchAuthorized": False,
        },
    }
    try:
        return SourceModeReport.model_validate(result).model_dump(by_alias=True, warnings="none")
    except ValidationError as error:
        raise SourceModeError(
            "Internal source-mode report does not satisfy its public contract."
        ) from error


def validate_build_record(data: object, plan_data: object) -> dict[str, Any]:
    """Accept only a non-executed record whose declared identities match its plan."""
    plan = _parse(plan_data)
    if isinstance(data, BuildRecord):
        data = data.model_dump(by_alias=True, warnings="none")
    try:
        record = BuildRecord.model_validate(data)
    except ValidationError as error:
        raise SourceModeError(
            "Invalid UI build record: " + ", ".join(_safe_error_fields(BuildRecord, error))
        ) from None
    if record.source_manifest_sha256 != plan.source.manifest_sha256:
        raise SourceModeError("Build record source identity differs from the plan.")
    if record.plan_sha256 != _plan_identity(plan):
        raise SourceModeError("Build record plan identity differs from the plan.")
    if record.recipe_revision != plan.recipe.revision or record.output_sha256 != plan.output.sha256:
        raise SourceModeError("Build record recipe or output identity differs from the plan.")
    return record.model_dump(by_alias=True, warnings="none")


def schema_documents() -> dict[str, dict[str, Any]]:
    """Return generated JSON Schemas for the public source-mode contracts."""
    return {
        "lab-ui-source-mode-v1.schema.json": SourceModePlan.model_json_schema(by_alias=True),
        "lab-ui-build-record-v1.schema.json": BuildRecord.model_json_schema(by_alias=True),
        "lab-ui-source-mode-report-v1.schema.json": SourceModeReport.model_json_schema(
            by_alias=True
        ),
    }
