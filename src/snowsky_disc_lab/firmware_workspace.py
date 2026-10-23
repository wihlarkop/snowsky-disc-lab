"""Private, quota-bounded firmware workspaces and a fixed synthetic output harness.

The synthetic harness recognizes one first-party fixture by content digest and
writes only fixed synthetic files. It does not extract proprietary firmware,
decrypt, mount, patch, or execute firmware.
"""

from __future__ import annotations

import builtins
import ctypes
import errno
import hashlib
import json
import os
import re
import stat
import sys
import time
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from snowsky_disc_lab.firmware_intake import (
    MAX_ARCHIVE_BYTES,
    MAX_DEPTH,
    MAX_ENTRIES,
    MAX_MEMBER_BYTES,
    MAX_TOTAL_BYTES,
    Condition,
    IntakeReceipt,
    _identity,
    _open_regular,
    _safe_name,
    inspect_firmware,
)

API_VERSION = "lab-firmware-workspace/v1"
OWNER_ID = "snowsky-disc-lab"

# These M1-03/V2.57 workspace limits bound local storage. They are not vendor
# firmware limits. Future extraction must use these quotas through this manager.
MAX_SNAPSHOT_BYTES = MAX_TOTAL_BYTES
MAX_SESSION_BYTES = 4 * 1024**3
MAX_STORE_BYTES = 8 * 1024**3
MAX_STORE_SESSIONS = 32
MAX_STORE_ENTRIES = 65_536
MAX_METADATA_BYTES = 256 * 1024
MAX_WORKSPACE_PATH_BYTES = 768
MAX_WORKSPACE_PATH_DEPTH = 16
MAX_IO_SECONDS = 300
COPY_BLOCK_BYTES = 64 * 1024
MAX_SYNTHETIC_OUTPUT_FILES = 2
MAX_SYNTHETIC_OUTPUT_FILE_BYTES = 8 * 1024
MAX_SYNTHETIC_OUTPUT_BYTES = 16 * 1024
SYNTHETIC_RECEIPT_RESERVE_BYTES = 16 * 1024
SYNTHETIC_FIXTURE_PACKAGE_SHA256 = (
    "21ae742cbc9cf0e191b818e9558109360f9aa4a3fdea1a16bb4ebe5f0c05644b"
)
SYNTHETIC_EXTRACTION_API_VERSION = "lab-firmware-synthetic-extraction/v1"
SYNTHETIC_EXTRACTION_OPERATION = "synthetic_fixture_materialization_v1"
_SYNTHETIC_OUTPUT_PATHS = ("synthetic-fixture.json", "synthetic-payload.bin")
_QUOTA_FAILURE_CODES = frozenset(
    {
        "workspace_quota_exceeded",
        "workspace_store_quota_exceeded",
        "workspace_session_quota_exceeded",
        "workspace_entry_limit",
        "workspace_store_entry_limit",
        "workspace_file_limit",
    }
)

_SHA256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
_SESSION_ID = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
]
_SESSION_ID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_FIRMWARE_ID = Annotated[str, StringConstraints(pattern=r"^sha256-[0-9a-f]{64}$")]
_ConditionStatus = Literal["verified", "unverified", "unsupported", "rejected"]
_ROOT_LAYOUT = ("staging", "workspaces", "quarantine")
_SAFE_WORKSPACE_COMPONENTS = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9_.-]*$")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, revalidate_instances="always"
    )


class WorkspaceReceipt(_FrozenModel):
    """Sanitized pathless report for one workspace operation."""

    api_version: Literal["lab-firmware-workspace/v1"] = API_VERSION
    operation_status: Literal["accepted", "refused"]
    state: Literal["none", "staging", "publishing", "finalized", "quarantined", "cleaned"]
    workspace_id: _SESSION_ID | None = None
    firmware_id: _FIRMWARE_ID | None = None
    input_format: Literal["zip", "directory", "unknown"] = "unknown"
    input_digest_kind: Literal["package_sha256"] = "package_sha256"
    input_digest: _SHA256 | None = None
    intake_receipt_sha256: _SHA256 | None = None
    intake: IntakeReceipt | None = None
    snapshot_files: int = 0
    snapshot_bytes: int = 0
    session_quota_bytes: int = MAX_SESSION_BYTES
    store_quota_bytes: int = MAX_STORE_BYTES
    created_at_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    conditions: list[Condition] = Field(default_factory=list)
    may_proceed: Literal[False] = False
    extraction_authorized: Literal[False] = False
    execution_authorized: Literal[False] = False
    compatibility: Literal["unverified"] = "unverified"
    vendor_authenticity: Literal["unverified"] = "unverified"

    @model_validator(mode="after")
    def validate_accepted_binding(self) -> WorkspaceReceipt:
        if self.operation_status != "accepted":
            return self
        if (
            self.state not in {"staging", "publishing", "finalized"}
            or self.workspace_id is None
            or self.intake is None
            or self.intake.status != "accepted"
            or self.input_format != self.intake.input_format
            or self.input_digest != self.intake.package_sha256
            or self.input_digest is None
            or self.firmware_id != f"sha256-{self.input_digest}"
            or self.intake_receipt_sha256 != _canonical_receipt_digest(self.intake)
        ):
            raise ValueError("accepted workspace receipt is not bound to its intake receipt")
        condition_map = {condition.check: condition for condition in self.conditions}
        if len(condition_map) != len(self.conditions):
            raise ValueError("accepted workspace receipt has duplicate conditions")
        fixed_conditions = {
            "vendor_authenticity": ("unverified", "no_reviewed_trust_chain"),
            "compatibility": ("unverified", "runtime_not_tested"),
            "extraction": ("unsupported", "outside_workspace_scope"),
        }
        for name, expected in fixed_conditions.items():
            condition = condition_map.get(name)
            if condition is None or (condition.status, condition.code) != expected:
                raise ValueError("accepted workspace receipt contradicts its fixed trust gates")
        execution = condition_map.get("execution")
        if (
            execution is None
            or execution.status != "unsupported"
            or execution.code
            not in {
                "workspace_state_staging",
                "workspace_state_publishing",
                "workspace_state_finalized",
            }
        ):
            raise ValueError("accepted workspace receipt contradicts its fixed trust gates")
        return self


class SyntheticOutputIdentity(_FrozenModel):
    """Content identity for one deterministic harness output."""

    path: Annotated[str, StringConstraints(min_length=1, max_length=MAX_WORKSPACE_PATH_BYTES)]
    size: int = Field(ge=0, le=MAX_SYNTHETIC_OUTPUT_FILE_BYTES)
    sha256: _SHA256


class SyntheticExtractionReceipt(_FrozenModel):
    """Pathless receipt for one fixed, first-party synthetic output operation."""

    api_version: Literal["lab-firmware-synthetic-extraction/v1"] = SYNTHETIC_EXTRACTION_API_VERSION
    operation_status: Literal["accepted", "refused"]
    state: Literal["refused", "incomplete", "published"]
    workspace_id: _SESSION_ID | None = None
    firmware_id: _FIRMWARE_ID | None = None
    input_digest: _SHA256 | None = None
    operation: Literal["synthetic_fixture_materialization_v1"] = SYNTHETIC_EXTRACTION_OPERATION
    operation_id: _SESSION_ID | None = None
    expected_output_manifest: list[SyntheticOutputIdentity] = Field(default_factory=list)
    output_manifest: list[SyntheticOutputIdentity] = Field(default_factory=list)
    output_file_count: int = Field(default=0, ge=0, le=MAX_SYNTHETIC_OUTPUT_FILES)
    output_bytes: int = Field(default=0, ge=0, le=MAX_SYNTHETIC_OUTPUT_BYTES)
    session_bytes_before: int | None = Field(default=None, ge=0, le=MAX_SESSION_BYTES)
    session_bytes_after: int | None = Field(default=None, ge=0, le=MAX_SESSION_BYTES)
    store_bytes_before: int | None = Field(default=None, ge=0, le=MAX_STORE_BYTES)
    store_bytes_after: int | None = Field(default=None, ge=0, le=MAX_STORE_BYTES)
    session_entries_before: int | None = Field(default=None, ge=0)
    session_entries_after: int | None = Field(default=None, ge=0)
    store_entries_before: int | None = Field(default=None, ge=0)
    store_entries_after: int | None = Field(default=None, ge=0)
    session_quota_bytes: int = MAX_SESSION_BYTES
    store_quota_bytes: int = MAX_STORE_BYTES
    publication_status: Literal["not_published", "published"] = "not_published"
    failure_code: Annotated[
        str | None,
        StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$"),
    ] = None
    conditions: list[Condition] = Field(default_factory=list)
    synthetic_only: Literal[True] = True
    may_proceed: Literal[False] = False
    extraction_authorized: Literal[False] = False
    execution_authorized: Literal[False] = False
    compatibility: Literal["unverified"] = "unverified"
    vendor_authenticity: Literal["unverified"] = "unverified"


class WorkspaceError(ValueError):
    """A fixed diagnostic code safe to return without filesystem details."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _OwnerMarker(_FrozenModel):
    api_version: Literal["lab-firmware-workspace-owner/v1"] = "lab-firmware-workspace-owner/v1"
    owner: Literal["snowsky-disc-lab"] = OWNER_ID
    workspace_id: _SESSION_ID
    root_device: int
    root_file_id: int
    workspace_device: int
    workspace_file_id: int


def default_workspace_root(cwd: Path | None = None) -> Path:
    """Return the ignored local workspace root for a checkout invocation."""
    base = Path.cwd() if cwd is None else cwd
    return Path(os.path.abspath(os.fspath(base / ".lab" / "firmware-workspaces")))


def _linked(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _file_id(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _identity_code(error: BaseException) -> str:
    if isinstance(error, WorkspaceError):
        return error.code
    return "workspace_io_refused"


def _check_directory(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError:
        raise WorkspaceError("workspace_path_unavailable") from None
    if _linked(info):
        raise WorkspaceError("unsafe_link_or_reparse_point")
    if not stat.S_ISDIR(info.st_mode):
        raise WorkspaceError("workspace_path_not_directory")
    return info


def _ensure_directory(path: Path) -> os.stat_result:
    absolute = Path(os.path.abspath(os.fspath(path)))
    for component in reversed((absolute, *absolute.parents)):
        try:
            info = component.lstat()
        except FileNotFoundError:
            try:
                component.mkdir(mode=0o700)
            except FileExistsError:
                pass
            except OSError:
                raise WorkspaceError("workspace_directory_create_failed") from None
            try:
                info = component.lstat()
            except OSError:
                raise WorkspaceError("workspace_path_unavailable") from None
        except OSError:
            raise WorkspaceError("workspace_path_unavailable") from None
        if _linked(info):
            raise WorkspaceError("unsafe_link_or_reparse_point")
        if not stat.S_ISDIR(info.st_mode):
            raise WorkspaceError("workspace_path_not_directory")
    if os.name != "nt":
        try:
            # Only restrict the managed directory itself. Never chmod ancestors
            # such as the checkout, home folder, or filesystem root.
            absolute.chmod(0o700)
        except OSError:
            raise WorkspaceError("workspace_permissions_failed") from None
    return _check_directory(absolute)


def _safe_components(path: Path) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    for component in reversed((absolute, *absolute.parents)):
        try:
            info = component.lstat()
        except OSError:
            raise WorkspaceError("workspace_path_unavailable") from None
        if _linked(info):
            raise WorkspaceError("unsafe_link_or_reparse_point")
        if component != absolute and not stat.S_ISDIR(info.st_mode):
            raise WorkspaceError("workspace_path_not_directory")


def _safe_workspace_name(name: str, *, directory: bool) -> None:
    if "\x00" in name or "\\" in name or len(name.encode("utf-8")) > MAX_WORKSPACE_PATH_BYTES:
        raise WorkspaceError("unsafe_workspace_path")
    parts = name.split("/")
    if not parts or len(parts) > MAX_WORKSPACE_PATH_DEPTH:
        raise WorkspaceError("workspace_path_depth_limit")
    for part in parts:
        _safe_name(part, directory=directory and part == parts[-1])


def _scan_entries(path: Path, *, maximum: int, code: str) -> list[os.DirEntry[str]]:
    try:
        entries: list[os.DirEntry[str]] = []
        with os.scandir(os.fspath(path)) as iterator:
            for entry in iterator:
                if len(entries) >= maximum:
                    raise WorkspaceError("workspace_entry_limit")
                entries.append(entry)
        return sorted(entries, key=lambda entry: entry.name)
    except WorkspaceError:
        raise
    except OSError:
        raise WorkspaceError(code) from None


def _read_regular(path: Path, *, maximum: int) -> bytes:
    try:
        expected = path.lstat()
        if (
            _linked(expected)
            or not stat.S_ISREG(expected.st_mode)
            or expected.st_nlink != 1
            or expected.st_size > maximum
        ):
            raise WorkspaceError("workspace_metadata_unsafe")
        with _open_regular(path, expected) as stream:
            value = stream.read(maximum + 1)
            if len(value) > maximum:
                raise WorkspaceError("workspace_metadata_limit")
            _safe_components(path)
            return value
    except WorkspaceError:
        raise
    except OSError:
        raise WorkspaceError("workspace_metadata_unreadable") from None


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise WorkspaceError("workspace_write_failed")
        offset += written


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        raise WorkspaceError("workspace_sync_failed") from None
    try:
        os.fsync(descriptor)
    except OSError:
        raise WorkspaceError("workspace_sync_failed") from None
    finally:
        os.close(descriptor)


def _atomic_json(path: Path, value: BaseModel, *, replace: bool) -> None:
    payload = (value.model_dump_json(indent=2) + "\n").encode("utf-8")
    if len(payload) > MAX_METADATA_BYTES:
        raise WorkspaceError("workspace_metadata_limit")
    parent = path.parent
    _safe_components(parent)
    parent_before = _check_directory(parent)
    temporary = parent / f"{path.name}.tmp-{uuid.uuid4().hex}"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, 0o600)
    except OSError:
        raise WorkspaceError("workspace_metadata_create_failed") from None
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    else:
        os.close(descriptor)
    try:
        _safe_components(parent)
        if _file_id(_check_directory(parent)) != _file_id(parent_before):
            raise WorkspaceError("workspace_changed")
        if replace:
            try:
                current = path.lstat()
            except FileNotFoundError:
                current = None
            except OSError:
                raise WorkspaceError("workspace_metadata_unsafe") from None
            if current is not None and (
                _linked(current) or not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
            ):
                raise WorkspaceError("workspace_metadata_unsafe")
            if current is not None:
                # Windows refuses replacement when the previous receipt has its
                # read-only attribute set. The manager lock serializes this update.
                path.chmod(0o600)
            os.replace(temporary, path)
        else:
            _publish_no_replace(temporary, path)
        try:
            path.chmod(0o400)
        except OSError:
            raise WorkspaceError("workspace_permissions_failed") from None
        _sync_directory(parent)
    except OSError:
        raise WorkspaceError("workspace_metadata_publish_failed") from None


@contextmanager
def _store_lock(root: Path) -> Generator[None]:
    """Serialize workspace mutations without relying on PID-based stale locks."""
    _safe_components(root)
    _check_directory(root)
    path = root / ".manager.lock"
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        info = os.fstat(descriptor)
        path_info = path.lstat()
        if (
            _linked(path_info)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or _identity(info) != _identity(path_info)
            or info.st_size > 4096
        ):
            raise WorkspaceError("workspace_lock_unsafe")
        if info.st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        if os.name == "nt":
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            except OSError:
                raise WorkspaceError("workspace_busy") from None
        else:
            import fcntl

            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[attr-defined]
            except OSError:
                raise WorkspaceError("workspace_busy") from None
    except WorkspaceError:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    except OSError:
        if "descriptor" in locals():
            os.close(descriptor)
        raise WorkspaceError("workspace_lock_failed") from None
    try:
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)  # type: ignore[attr-defined]
        finally:
            os.close(descriptor)


def _publish_no_replace(staging: Path, destination: Path) -> None:
    """Atomically publish one same-volume directory without replacing a peer."""
    if os.name == "nt":
        # Windows rename fails when the destination exists and is same-volume atomic.
        os.rename(staging, destination)
        return
    if not sys.platform.startswith("linux"):
        raise WorkspaceError("atomic_no_replace_unsupported")
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError):
        raise WorkspaceError("atomic_no_replace_unsupported") from None
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(-100, os.fsencode(staging), -100, os.fsencode(destination), 1)
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise WorkspaceError("workspace_destination_exists")
    if error_number == errno.EXDEV:
        raise WorkspaceError("workspace_cross_device_publish")
    if error_number in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
        raise WorkspaceError("atomic_no_replace_unsupported")
    raise WorkspaceError("workspace_publish_failed")


def _canonical_receipt_digest(receipt: IntakeReceipt) -> str:
    serialized = json.dumps(
        receipt.model_dump(mode="json"), ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(serialized).hexdigest()


def _receipt_digest(receipt: IntakeReceipt) -> str | None:
    return receipt.package_sha256 if receipt.status == "accepted" else None


def _input_kind(receipt: IntakeReceipt) -> Literal["zip", "directory", "unknown"]:
    if receipt.input_format == "zip":
        return "zip"
    if receipt.input_format == "directory":
        return "directory"
    return "unknown"


def _workspace_conditions(
    *,
    snapshot_verified: bool,
    state: str,
    workspace_owned: bool = False,
    quota_verified: bool = False,
) -> list[Condition]:
    return [
        Condition(
            check="input_snapshot",
            status="verified" if snapshot_verified else "unverified",
            code="content_digest_match" if snapshot_verified else "snapshot_not_finalized",
        ),
        Condition(
            check="workspace_ownership",
            status="verified" if workspace_owned else "unverified",
            code="owned_session_directory"
            if workspace_owned
            else "workspace_not_created"
            if state == "none"
            else "ownership_not_established",
        ),
        Condition(
            check="workspace_quota",
            status="verified" if quota_verified else "unverified",
            code="bounded_workspace_policy" if quota_verified else "workspace_quota_not_measured",
        ),
        Condition(
            check="vendor_authenticity",
            status="unverified",
            code="no_reviewed_trust_chain",
        ),
        Condition(check="compatibility", status="unverified", code="runtime_not_tested"),
        Condition(check="extraction", status="unsupported", code="outside_workspace_scope"),
        Condition(check="execution", status="unsupported", code=f"workspace_state_{state}"),
    ]


def _refused_receipt(
    code: str,
    *,
    intake: IntakeReceipt | None = None,
    workspace_id: str | None = None,
    firmware_id: str | None = None,
    state: Literal["none", "staging", "publishing", "finalized", "quarantined", "cleaned"] = "none",
    snapshot_files: int = 0,
    snapshot_bytes: int = 0,
    workspace_owned: bool = False,
    quota_verified: bool = False,
) -> WorkspaceReceipt:
    return WorkspaceReceipt(
        operation_status="refused",
        state=state,
        workspace_id=workspace_id,
        firmware_id=firmware_id,
        input_format=_input_kind(intake) if intake is not None else "unknown",
        input_digest_kind="package_sha256",
        input_digest=_receipt_digest(intake) if intake is not None else None,
        intake_receipt_sha256=_canonical_receipt_digest(intake) if intake is not None else None,
        intake=intake,
        snapshot_files=snapshot_files,
        snapshot_bytes=snapshot_bytes,
        conditions=[
            Condition(check="workspace", status="rejected", code=code),
            *_workspace_conditions(
                snapshot_verified=False,
                state=state,
                workspace_owned=workspace_owned,
                quota_verified=quota_verified,
            ),
        ],
    )


def _accepted_receipt(
    intake: IntakeReceipt,
    *,
    workspace_id: str,
    state: Literal["staging", "publishing", "finalized", "quarantined", "cleaned"],
    snapshot_files: int,
    snapshot_bytes: int,
    snapshot_verified: bool,
    workspace_owned: bool = False,
    quota_verified: bool = False,
) -> WorkspaceReceipt:
    digest = intake.package_sha256
    if digest is None:
        raise WorkspaceError("intake_digest_missing")
    return WorkspaceReceipt(
        operation_status="accepted",
        state=state,
        workspace_id=workspace_id,
        firmware_id=f"sha256-{digest}",
        input_format=_input_kind(intake),
        input_digest_kind="package_sha256",
        input_digest=digest,
        intake_receipt_sha256=_canonical_receipt_digest(intake),
        intake=intake,
        snapshot_files=snapshot_files,
        snapshot_bytes=snapshot_bytes,
        conditions=_workspace_conditions(
            snapshot_verified=snapshot_verified,
            state=state,
            workspace_owned=workspace_owned,
            quota_verified=quota_verified,
        ),
    )


def _same_intake(left: IntakeReceipt, right: IntakeReceipt) -> bool:
    return left.status == "accepted" and right.status == "accepted" and left == right


def _check_id(session_id: str) -> str:
    try:
        return str(uuid.UUID(session_id))
    except (ValueError, AttributeError):
        raise WorkspaceError("invalid_workspace_id") from None


def _directory_entries(root: Path, *, deadline: float) -> list[tuple[str, Path, os.stat_result]]:
    result: list[tuple[str, Path, os.stat_result]] = []
    try:
        root_device = root.lstat().st_dev
    except OSError:
        raise WorkspaceError("input_changed") from None
    pending: list[tuple[Path, str, int]] = [(root, "", 0)]
    entry_count = 0
    while pending:
        if time.monotonic() > deadline:
            raise WorkspaceError("workspace_time_limit")
        current, prefix, depth = pending.pop()
        children = _scan_entries(current, maximum=MAX_ENTRIES, code="input_enumeration_failed")
        for child in children:
            entry_count += 1
            if entry_count > MAX_ENTRIES:
                raise WorkspaceError("entry_count_limit")
            relative = f"{prefix}/{child.name}" if prefix else child.name
            try:
                info = Path(child.path).lstat()
            except OSError:
                raise WorkspaceError("input_changed") from None
            if _linked(info):
                raise WorkspaceError("unsafe_link_or_reparse_point")
            if info.st_dev != root_device:
                raise WorkspaceError("input_mount_boundary")
            is_directory = stat.S_ISDIR(info.st_mode)
            if not is_directory and not stat.S_ISREG(info.st_mode):
                raise WorkspaceError("unsupported_input_file_type")
            _safe_name(relative, directory=is_directory)
            if is_directory:
                if depth + 1 > MAX_DEPTH:
                    raise WorkspaceError("path_depth_limit")
                pending.append((Path(child.path), relative, depth + 1))
            else:
                if info.st_nlink != 1:
                    raise WorkspaceError("hard_link_unsupported")
                result.append((relative, Path(child.path), info))
    return result


def _copy_stream(
    source: Path,
    expected: os.stat_result,
    destination: Path,
    *,
    max_bytes: int,
    deadline: float,
) -> tuple[int, str]:
    if expected.st_size > max_bytes:
        raise WorkspaceError("workspace_file_limit")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        target_descriptor = os.open(destination, flags, 0o600)
    except OSError:
        raise WorkspaceError("workspace_snapshot_create_failed") from None
    digest = hashlib.sha256()
    copied = 0
    try:
        with _open_regular(source, expected) as input_stream:
            while True:
                if time.monotonic() > deadline:
                    raise WorkspaceError("workspace_time_limit")
                block = input_stream.read(COPY_BLOCK_BYTES)
                if not block:
                    break
                copied += len(block)
                if copied > max_bytes:
                    raise WorkspaceError("workspace_file_limit")
                digest.update(block)
                _write_all(target_descriptor, block)
        if copied != expected.st_size:
            raise WorkspaceError("input_changed")
        os.fsync(target_descriptor)
    except BaseException:
        os.close(target_descriptor)
        raise
    else:
        os.close(target_descriptor)
    try:
        destination.chmod(0o400)
    except OSError:
        raise WorkspaceError("workspace_permissions_failed") from None
    return copied, digest.hexdigest()


def _copy_directory(
    source: Path, destination: Path, *, deadline: float, expected_digest: str
) -> tuple[int, int]:
    entries = _directory_entries(source, deadline=deadline)
    _ensure_directory(destination)
    directories: list[Path] = []
    total = 0
    inventory: list[list[object]] = []
    for relative, source_file, expected in entries:
        if time.monotonic() > deadline:
            raise WorkspaceError("workspace_time_limit")
        if expected.st_size > MAX_MEMBER_BYTES:
            raise WorkspaceError("workspace_file_limit")
        total += expected.st_size
        if total > MAX_SNAPSHOT_BYTES:
            raise WorkspaceError("workspace_snapshot_limit")
        target = destination.joinpath(*relative.split("/"))
        _ensure_directory(target.parent)
        size, digest = _copy_stream(
            source_file, expected, target, max_bytes=MAX_MEMBER_BYTES, deadline=deadline
        )
        inventory.append([relative, size, digest])
    # Empty directories carry no firmware bytes, but preserve their safe layout.
    for _directory, prefix, _ in _directory_stack(source, deadline=deadline):
        if prefix:
            target_dir = destination.joinpath(*prefix.split("/"))
            _ensure_directory(target_dir)
            directories.append(target_dir)
    for directory in sorted(set(directories), key=lambda item: len(item.parts), reverse=True):
        try:
            directory.chmod(0o500)
        except OSError:
            raise WorkspaceError("workspace_permissions_failed") from None
    observed_digest = hashlib.sha256(
        # M1-02 package identity is the sorted path/size/content-hash inventory.
        json.dumps(
            sorted(inventory, key=lambda row: row[0]), ensure_ascii=True, separators=(",", ":")
        ).encode("ascii")
    ).hexdigest()
    if observed_digest != expected_digest:
        raise WorkspaceError("input_changed")
    try:
        destination.chmod(0o500)
    except OSError:
        raise WorkspaceError("workspace_permissions_failed") from None
    return len(entries), total


def _directory_stack(root: Path, *, deadline: float) -> list[tuple[Path, str, int]]:
    result: list[tuple[Path, str, int]] = []
    try:
        root_device = root.lstat().st_dev
    except OSError:
        raise WorkspaceError("input_changed") from None
    pending: list[tuple[Path, str, int]] = [(root, "", 0)]
    entry_count = 0
    while pending:
        if time.monotonic() > deadline:
            raise WorkspaceError("workspace_time_limit")
        current, prefix, depth = pending.pop()
        children = _scan_entries(current, maximum=MAX_ENTRIES, code="input_enumeration_failed")
        for child in children:
            entry_count += 1
            if entry_count > MAX_ENTRIES:
                raise WorkspaceError("entry_count_limit")
            name = f"{prefix}/{child.name}" if prefix else child.name
            try:
                info = Path(child.path).lstat()
            except OSError:
                raise WorkspaceError("input_changed") from None
            if _linked(info):
                raise WorkspaceError("unsafe_link_or_reparse_point")
            if info.st_dev != root_device:
                raise WorkspaceError("input_mount_boundary")
            if stat.S_ISDIR(info.st_mode):
                _safe_name(name, directory=True)
                if depth + 1 > MAX_DEPTH:
                    raise WorkspaceError("path_depth_limit")
                result.append((Path(child.path), name, depth + 1))
                pending.append((Path(child.path), name, depth + 1))
            elif not stat.S_ISREG(info.st_mode):
                raise WorkspaceError("unsupported_input_file_type")
    return result


def _snapshot_input(
    candidate: Path, intake: IntakeReceipt, workspace: Path, *, deadline: float
) -> tuple[int, int]:
    input_root = workspace / "inputs"
    _ensure_directory(input_root)
    if intake.input_format == "zip":
        try:
            expected = candidate.lstat()
        except OSError:
            raise WorkspaceError("input_changed") from None
        size, digest = _copy_stream(
            candidate,
            expected,
            input_root / "original.zip",
            max_bytes=MAX_ARCHIVE_BYTES,
            deadline=deadline,
        )
        if digest != intake.archive_sha256:
            raise WorkspaceError("input_changed")
        try:
            input_root.chmod(0o500)
        except OSError:
            raise WorkspaceError("workspace_permissions_failed") from None
        return 1, size
    if intake.input_format == "directory":
        if intake.package_sha256 is None:
            raise WorkspaceError("intake_digest_missing")
        count, size = _copy_directory(
            candidate,
            input_root / "package",
            deadline=deadline,
            expected_digest=intake.package_sha256,
        )
        try:
            input_root.chmod(0o500)
        except OSError:
            raise WorkspaceError("workspace_permissions_failed") from None
        return count, size
    raise WorkspaceError("unsupported_input_type")


def _workspace_entry_estimate(candidate: Path, input_format: str, *, deadline: float) -> int:
    # Two metadata files and four reserved area directories are present for all
    # sessions. A ZIP adds one file; a directory adds its package root plus all
    # selected input files and subdirectories.
    if input_format == "zip":
        return 7
    if input_format == "directory":
        return (
            7
            + len(_directory_entries(candidate, deadline=deadline))
            + len(_directory_stack(candidate, deadline=deadline))
        )
    raise WorkspaceError("unsupported_input_type")


def _safe_tree(
    root: Path,
    *,
    deadline: float,
    max_entries: int,
    max_bytes: int,
    expected_device: int,
) -> tuple[int, int]:
    _check_directory(root)
    pending: list[tuple[Path, str, int]] = [(root, "", 0)]
    count = 0
    total = 0
    while pending:
        if time.monotonic() > deadline:
            raise WorkspaceError("workspace_time_limit")
        current, prefix, depth = pending.pop()
        children = _scan_entries(current, maximum=max_entries, code="workspace_enumeration_failed")
        for child in children:
            name = child.name
            relative = f"{prefix}/{name}" if prefix else name
            try:
                info = Path(child.path).lstat()
            except OSError:
                raise WorkspaceError("workspace_changed") from None
            if _linked(info):
                raise WorkspaceError("unsafe_link_or_reparse_point")
            if info.st_dev != expected_device:
                raise WorkspaceError("workspace_mount_boundary")
            is_directory = stat.S_ISDIR(info.st_mode)
            _safe_workspace_name(relative, directory=is_directory)
            count += 1
            if count > max_entries:
                raise WorkspaceError("workspace_entry_limit")
            if stat.S_ISDIR(info.st_mode):
                if depth + 1 > MAX_WORKSPACE_PATH_DEPTH:
                    raise WorkspaceError("workspace_path_depth_limit")
                pending.append((Path(child.path), relative, depth + 1))
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise WorkspaceError("hard_link_unsupported")
                file_limit = (
                    MAX_ARCHIVE_BYTES
                    if relative == "inputs/original.zip"
                    else MAX_METADATA_BYTES
                    if name in {"owner.json", "workspace.json"}
                    or name.startswith(("owner.json.tmp-", "workspace.json.tmp-"))
                    else MAX_MEMBER_BYTES
                )
                if info.st_size > file_limit:
                    raise WorkspaceError("workspace_file_limit")
                total += info.st_size
                if total > max_bytes:
                    raise WorkspaceError("workspace_quota_exceeded")
            else:
                raise WorkspaceError("workspace_file_type_unsupported")
    return count, total


def _session_locations(root: Path, session_id: str) -> list[tuple[str, Path]]:
    paths = [
        ("staging", root / "staging" / session_id),
        ("quarantined", root / "quarantine" / session_id),
    ]
    workspace_root = root / "workspaces"
    if os.path.lexists(workspace_root):
        for package_dir in _scan_entries(
            workspace_root, maximum=MAX_STORE_SESSIONS, code="workspace_enumeration_failed"
        ):
            if not _SAFE_WORKSPACE_COMPONENTS.fullmatch(package_dir.name):
                continue
            paths.append(("finalized", Path(package_dir.path) / session_id))
    return [(state, path) for state, path in paths if os.path.lexists(path)]


def _parse_owner(
    path: Path, root_info: os.stat_result, session_info: os.stat_result
) -> _OwnerMarker:
    raw = _read_regular(path / "owner.json", maximum=MAX_METADATA_BYTES)
    try:
        json.loads(raw, object_pairs_hook=_unique_json_object)
        marker = _OwnerMarker.model_validate_json(raw)
    except (ValidationError, ValueError, RecursionError):
        raise WorkspaceError("workspace_owner_invalid") from None
    if (
        marker.root_device != root_info.st_dev
        or marker.root_file_id != root_info.st_ino
        or marker.workspace_device != session_info.st_dev
        or marker.workspace_file_id != session_info.st_ino
    ):
        raise WorkspaceError("workspace_identity_mismatch")
    return marker


def _load_receipt(path: Path) -> WorkspaceReceipt:
    raw = _read_regular(path / "workspace.json", maximum=MAX_METADATA_BYTES)
    try:
        json.loads(raw, object_pairs_hook=_unique_json_object)
        return WorkspaceReceipt.model_validate_json(raw)
    except (ValidationError, ValueError, RecursionError):
        raise WorkspaceError("workspace_receipt_invalid") from None


def _measure_store(root: Path, *, deadline: float) -> tuple[int, int, int]:
    _safe_components(root)
    root_info = _check_directory(root)
    total_bytes = 0
    total_entries = 0
    sessions = 0
    for category in _ROOT_LAYOUT:
        category_path = root / category
        _check_directory(category_path)
        children = _scan_entries(
            category_path, maximum=MAX_STORE_SESSIONS, code="workspace_enumeration_failed"
        )
        for child in children:
            if time.monotonic() > deadline:
                raise WorkspaceError("workspace_time_limit")
            path = Path(child.path)
            info = _check_directory(path)
            if info.st_dev != root_info.st_dev:
                raise WorkspaceError("workspace_mount_boundary")
            if category == "workspaces":
                if not re.fullmatch(r"sha256-[0-9a-f]{64}", child.name):
                    raise WorkspaceError("workspace_layout_unsupported")
                nested = _scan_entries(
                    path, maximum=MAX_STORE_SESSIONS, code="workspace_enumeration_failed"
                )
                for session_entry in nested:
                    session_path = Path(session_entry.path)
                    session_info = _check_directory(session_path)
                    if _check_id(session_entry.name) != session_entry.name:
                        raise WorkspaceError("workspace_layout_unsupported")
                    _parse_owner(session_path, root_info, session_info)
                    sessions += 1
                    count, size = _safe_tree(
                        session_path,
                        deadline=deadline,
                        max_entries=MAX_ENTRIES + 16,
                        max_bytes=MAX_SESSION_BYTES,
                        expected_device=root_info.st_dev,
                    )
                    total_entries += count
                    total_bytes += size
            else:
                _check_id(child.name)
                _parse_owner(path, root_info, info)
                sessions += 1
                count, size = _safe_tree(
                    path,
                    deadline=deadline,
                    max_entries=MAX_ENTRIES + 16,
                    max_bytes=MAX_SESSION_BYTES,
                    expected_device=root_info.st_dev,
                )
                total_entries += count
                total_bytes += size
            if sessions > MAX_STORE_SESSIONS:
                raise WorkspaceError("workspace_session_limit")
            if total_entries > MAX_STORE_ENTRIES:
                raise WorkspaceError("workspace_store_entry_limit")
            if total_bytes > MAX_STORE_BYTES:
                raise WorkspaceError("workspace_store_quota_exceeded")
    return sessions, total_entries, total_bytes


def _owned_workspace(
    root: Path, session_id: str
) -> tuple[str, Path, os.stat_result, WorkspaceReceipt]:
    locations = _session_locations(root, session_id)
    if len(locations) != 1:
        raise WorkspaceError("workspace_not_found" if not locations else "workspace_ambiguous")
    state, path = locations[0]
    _safe_components(path.parent)
    root_info = _check_directory(root)
    path_info = _check_directory(path)
    if path_info.st_dev != root_info.st_dev:
        raise WorkspaceError("workspace_mount_boundary")
    marker = _parse_owner(path, root_info, path_info)
    if marker.workspace_id != session_id:
        raise WorkspaceError("workspace_identity_mismatch")
    receipt = _load_receipt(path)
    if receipt.workspace_id != session_id:
        raise WorkspaceError("workspace_identity_mismatch")
    expected_state = state
    if state == "finalized" and receipt.state != "finalized":
        raise WorkspaceError("workspace_state_mismatch")
    if state == "staging" and receipt.state not in {"staging", "publishing"}:
        raise WorkspaceError("workspace_state_mismatch")
    if state == "quarantined" and receipt.state != "quarantined":
        raise WorkspaceError("workspace_state_mismatch")
    if expected_state not in {"staging", "finalized", "quarantined"}:
        raise WorkspaceError("workspace_state_mismatch")
    return state, path, path_info, receipt


def _copy_identity_matches(receipt: IntakeReceipt, snapshot: IntakeReceipt) -> bool:
    return snapshot.status == "accepted" and receipt == snapshot


def _workspace_snapshot_path(workspace: Path, receipt: WorkspaceReceipt) -> Path:
    if receipt.input_format == "zip":
        return workspace / "inputs" / "original.zip"
    if receipt.input_format == "directory":
        return workspace / "inputs" / "package"
    raise WorkspaceError("workspace_input_format_unknown")


def _verify_snapshot(workspace: Path, receipt: WorkspaceReceipt) -> IntakeReceipt:
    if receipt.intake is None or receipt.intake.status != "accepted":
        raise WorkspaceError("intake_receipt_unavailable")
    snapshot_path = _workspace_snapshot_path(workspace, receipt)
    observed = inspect_firmware(snapshot_path)
    if not _copy_identity_matches(receipt.intake, observed):
        raise WorkspaceError("workspace_snapshot_mismatch")
    if receipt.input_digest != observed.package_sha256:
        raise WorkspaceError("workspace_snapshot_mismatch")
    return observed


def _synthetic_output_files(input_digest: str) -> tuple[tuple[str, bytes], ...]:
    """Return the fixed output bytes for the one pinned synthetic package."""
    summary = (
        json.dumps(
            {
                "api_version": "snowsky-disc-lab-synthetic-fixture/v1",
                "fixture": "first-party-synthetic-only",
                "input_package_sha256": input_digest,
                "rootfs_chunk_count": 77,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )
    payload = b"SNOWSKY-DISC-LAB SYNTHETIC PAYLOAD V1\n" + bytes.fromhex(input_digest)
    content = (summary, payload)
    return tuple((name, content[index]) for index, name in enumerate(_SYNTHETIC_OUTPUT_PATHS))


def _synthetic_manifest(
    output_files: tuple[tuple[str, bytes], ...],
) -> list[SyntheticOutputIdentity]:
    return [
        SyntheticOutputIdentity(
            path=name, size=len(content), sha256=hashlib.sha256(content).hexdigest()
        )
        for name, content in sorted(output_files)
    ]


def _validate_synthetic_output_files(
    output_files: tuple[tuple[str, bytes], ...],
) -> tuple[int, int]:
    names: set[str] = set()
    total_bytes = 0
    for name, content in output_files:
        if not isinstance(name, str):
            raise WorkspaceError("synthetic_output_spec_invalid")
        try:
            _safe_workspace_name(name, directory=False)
        except (ValueError, UnicodeError):
            raise WorkspaceError("unsafe_synthetic_output_path") from None
        normalized = name.casefold()
        if normalized in names:
            raise WorkspaceError("synthetic_output_path_collision")
        names.add(normalized)
        if len(content) > MAX_SYNTHETIC_OUTPUT_FILE_BYTES:
            raise WorkspaceError("synthetic_output_file_limit")
        total_bytes += len(content)
    if len(output_files) != MAX_SYNTHETIC_OUTPUT_FILES:
        raise WorkspaceError("synthetic_output_spec_invalid")
    if total_bytes > MAX_SYNTHETIC_OUTPUT_BYTES:
        raise WorkspaceError("synthetic_output_total_limit")
    return len(output_files), total_bytes


def _write_synthetic_output(
    output_root: Path,
    relative: str,
    content: bytes,
    *,
    expected_device: int,
) -> SyntheticOutputIdentity:
    """Create one fixed output below a checked, owned extraction directory."""
    try:
        _safe_workspace_name(relative, directory=False)
    except (ValueError, UnicodeError):
        raise WorkspaceError("unsafe_synthetic_output_path") from None
    if len(content) > MAX_SYNTHETIC_OUTPUT_FILE_BYTES:
        raise WorkspaceError("synthetic_output_file_limit")
    root_info = _check_directory(output_root)
    if root_info.st_dev != expected_device:
        raise WorkspaceError("workspace_mount_boundary")
    parts = relative.split("/")
    parent = output_root
    for part in parts[:-1]:
        parent = parent / part
        try:
            parent_info = parent.lstat()
        except FileNotFoundError:
            _ensure_directory(parent)
            parent_info = parent.lstat()
        except OSError:
            raise WorkspaceError("synthetic_output_parent_unavailable") from None
        if _linked(parent_info) or not stat.S_ISDIR(parent_info.st_mode):
            raise WorkspaceError("unsafe_synthetic_output_parent")
        if parent_info.st_dev != expected_device:
            raise WorkspaceError("workspace_mount_boundary")
    destination = parent / parts[-1]
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(destination, flags, 0o600)
    except FileExistsError:
        raise WorkspaceError("synthetic_output_already_exists") from None
    except OSError:
        raise WorkspaceError("synthetic_output_create_failed") from None
    try:
        _write_all(descriptor, content)
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    else:
        os.close(descriptor)
    try:
        destination.chmod(0o400)
        _sync_directory(parent)
    except OSError:
        raise WorkspaceError("synthetic_output_permissions_failed") from None
    return SyntheticOutputIdentity(
        path=relative,
        size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )


def _verify_synthetic_output_tree(
    output_root: Path,
    expected_files: tuple[tuple[str, bytes], ...],
    *,
    expected_device: int,
) -> list[SyntheticOutputIdentity]:
    """Read back and compare the complete fixed output tree before publication."""
    expected_by_name = dict(expected_files)
    try:
        entries = _directory_entries(output_root, deadline=time.monotonic() + MAX_IO_SECONDS)
        observed_names = {name for name, _path, _info in entries}
        if observed_names != set(expected_by_name):
            if observed_names < set(expected_by_name):
                raise WorkspaceError("synthetic_output_missing")
            raise WorkspaceError("synthetic_output_path_mismatch")
        directory_entries, total_bytes = _safe_tree(
            output_root,
            deadline=time.monotonic() + MAX_IO_SECONDS,
            max_entries=MAX_SYNTHETIC_OUTPUT_FILES + MAX_WORKSPACE_PATH_DEPTH,
            max_bytes=MAX_SYNTHETIC_OUTPUT_BYTES,
            expected_device=expected_device,
        )
        expected_directories = {
            "/".join(name.split("/")[:index])
            for name in expected_by_name
            for index in range(1, len(name.split("/")))
        }
        if directory_entries != len(expected_by_name) + len(expected_directories):
            raise WorkspaceError("synthetic_output_path_mismatch")
        if total_bytes > MAX_SYNTHETIC_OUTPUT_BYTES:
            raise WorkspaceError("synthetic_output_total_limit")
        records: list[SyntheticOutputIdentity] = []
        for name in sorted(expected_by_name):
            path = output_root.joinpath(*name.split("/"))
            content = _read_regular(path, maximum=MAX_SYNTHETIC_OUTPUT_FILE_BYTES)
            if content != expected_by_name[name]:
                raise WorkspaceError("synthetic_output_digest_mismatch")
            records.append(
                SyntheticOutputIdentity(
                    path=name,
                    size=len(content),
                    sha256=hashlib.sha256(content).hexdigest(),
                )
            )
        return records
    except WorkspaceError:
        raise
    except (OSError, ValueError, UnicodeError):
        raise WorkspaceError("synthetic_output_verification_failed") from None


def _observe_synthetic_output_tree(
    output_root: Path,
    *,
    expected_device: int,
) -> list[SyntheticOutputIdentity]:
    """Hash bounded files left by a failed write for the incomplete receipt."""
    root_info = _check_directory(output_root)
    if root_info.st_dev != expected_device:
        raise WorkspaceError("workspace_mount_boundary")
    entries = _directory_entries(output_root, deadline=time.monotonic() + MAX_IO_SECONDS)
    if len(entries) > MAX_SYNTHETIC_OUTPUT_FILES:
        raise WorkspaceError("synthetic_output_file_count_limit")
    records: list[SyntheticOutputIdentity] = []
    total_bytes = 0
    for name, path, _info in entries:
        content = _read_regular(path, maximum=MAX_SYNTHETIC_OUTPUT_FILE_BYTES)
        total_bytes += len(content)
        if total_bytes > MAX_SYNTHETIC_OUTPUT_BYTES:
            raise WorkspaceError("synthetic_output_total_limit")
        records.append(
            SyntheticOutputIdentity(
                path=name,
                size=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
            )
        )
    return records


def _synthetic_conditions(
    *,
    ownership: _ConditionStatus = "unverified",
    snapshot: _ConditionStatus = "unverified",
    fixture: _ConditionStatus = "unverified",
    output_paths: _ConditionStatus = "unverified",
    output: _ConditionStatus = "unverified",
    quota: _ConditionStatus = "unverified",
    publication: _ConditionStatus = "unverified",
) -> list[Condition]:
    return [
        Condition(
            check="workspace_ownership",
            status=ownership,
            code="owned_session" if ownership == "verified" else "ownership_not_established",
        ),
        Condition(
            check="input_snapshot",
            status=snapshot,
            code="content_digest_match" if snapshot == "verified" else "snapshot_not_verified",
        ),
        Condition(
            check="synthetic_fixture_identity",
            status=fixture,
            code="pinned_first_party_fixture"
            if fixture == "verified"
            else "synthetic_fixture_identity_mismatch"
            if fixture == "rejected"
            else "fixture_identity_not_verified",
        ),
        Condition(
            check="output_path_safety",
            status=output_paths,
            code="fixed_safe_output_paths"
            if output_paths == "verified"
            else "unsafe_output_path"
            if output_paths == "rejected"
            else "output_paths_not_verified",
        ),
        Condition(
            check="output_integrity",
            status=output,
            code="output_hashes_match"
            if output == "verified"
            else "output_integrity_failed"
            if output == "rejected"
            else "output_not_verified",
        ),
        Condition(
            check="workspace_quota",
            status=quota,
            code="bounded_store_measurement"
            if quota == "verified"
            else "workspace_quota_refused"
            if quota == "rejected"
            else "workspace_quota_not_measured",
        ),
        Condition(
            check="output_publication",
            status=publication,
            code="no_replace_publish"
            if publication == "verified"
            else "publication_refused"
            if publication == "rejected"
            else "not_published",
        ),
        Condition(check="vendor_authenticity", status="unverified", code="no_reviewed_trust_chain"),
        Condition(check="compatibility", status="unverified", code="runtime_not_tested"),
        Condition(
            check="real_firmware_extraction", status="unsupported", code="synthetic_harness_only"
        ),
        Condition(check="execution", status="unsupported", code="not_implemented"),
    ]


def _synthetic_refusal(
    code: str,
    *,
    workspace_id: str | None = None,
    firmware_id: str | None = None,
    input_digest: str | None = None,
    operation_id: str | None = None,
    expected_output_manifest: list[SyntheticOutputIdentity] | None = None,
    output_manifest: list[SyntheticOutputIdentity] | None = None,
    session_bytes_before: int | None = None,
    session_bytes_after: int | None = None,
    store_bytes_before: int | None = None,
    store_bytes_after: int | None = None,
    session_entries_before: int | None = None,
    session_entries_after: int | None = None,
    store_entries_before: int | None = None,
    store_entries_after: int | None = None,
    ownership: _ConditionStatus = "unverified",
    snapshot: _ConditionStatus = "unverified",
    fixture: _ConditionStatus = "unverified",
    output_paths: _ConditionStatus = "unverified",
    output: _ConditionStatus = "unverified",
    quota: _ConditionStatus = "unverified",
    publication: _ConditionStatus = "rejected",
    state: Literal["refused", "incomplete", "published"] = "refused",
    publication_status: Literal["not_published", "published"] = "not_published",
) -> SyntheticExtractionReceipt:
    observed_outputs = output_manifest or []
    return SyntheticExtractionReceipt(
        operation_status="refused",
        state=state,
        workspace_id=workspace_id,
        firmware_id=firmware_id,
        input_digest=input_digest,
        operation_id=operation_id,
        expected_output_manifest=expected_output_manifest or [],
        output_manifest=observed_outputs,
        output_file_count=len(observed_outputs),
        output_bytes=sum(item.size for item in observed_outputs),
        session_bytes_before=session_bytes_before,
        session_bytes_after=session_bytes_after,
        store_bytes_before=store_bytes_before,
        store_bytes_after=store_bytes_after,
        session_entries_before=session_entries_before,
        session_entries_after=session_entries_after,
        store_entries_before=store_entries_before,
        store_entries_after=store_entries_after,
        publication_status=publication_status,
        failure_code=code,
        conditions=_synthetic_conditions(
            ownership=ownership,
            snapshot=snapshot,
            fixture=fixture,
            output_paths=output_paths,
            output=output,
            quota=quota,
            publication=publication,
        ),
    )


def _empty_staging_workspace(workspace: Path) -> bool:
    entries = _scan_entries(workspace, maximum=16, code="workspace_enumeration_failed")
    expected_files = {"owner.json", "workspace.json"}
    found_files: set[str] = set()
    allowed_dirs = {"inputs", "intermediate", "extraction", "diagnostics"}
    for entry in entries:
        path = Path(entry.path)
        info = path.lstat()
        if _linked(info):
            raise WorkspaceError("unsafe_link_or_reparse_point")
        if stat.S_ISREG(info.st_mode) and entry.name in expected_files and info.st_nlink == 1:
            found_files.add(entry.name)
        elif stat.S_ISDIR(info.st_mode) and entry.name in allowed_dirs:
            if _scan_entries(path, maximum=1, code="workspace_enumeration_failed"):
                return False
        else:
            return False
    return found_files == expected_files


def _remove_empty_staging(workspace: Path, expected: os.stat_result) -> None:
    if _file_id(_check_directory(workspace)) != _file_id(expected):
        raise WorkspaceError("workspace_changed")
    if not _empty_staging_workspace(workspace):
        raise WorkspaceError("staging_contains_retained_input")
    for name in ("inputs", "intermediate", "extraction", "diagnostics"):
        path = workspace / name
        try:
            path.rmdir()
        except FileNotFoundError:
            continue
        except OSError:
            raise WorkspaceError("workspace_cleanup_refused") from None
    for name in ("workspace.json", "owner.json"):
        path = workspace / name
        try:
            info = path.lstat()
        except OSError:
            raise WorkspaceError("workspace_cleanup_refused") from None
        if _linked(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise WorkspaceError("workspace_cleanup_refused")
        path.unlink()
    try:
        workspace.rmdir()
    except OSError:
        raise WorkspaceError("workspace_cleanup_refused") from None


class FirmwareWorkspaceManager:
    """Manage private input snapshots and isolated per-session workspaces."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(
            os.path.abspath(os.fspath(default_workspace_root() if root is None else root))
        )

    def _prepare_store(self) -> os.stat_result:
        _ensure_directory(self.root)
        for category in _ROOT_LAYOUT:
            _ensure_directory(self.root / category)
        return _check_directory(self.root)

    def stage(self, candidate: Path) -> WorkspaceReceipt:
        """Create a private staged byte snapshot after fresh intake inspections."""
        first = inspect_firmware(candidate)
        if first.status != "accepted" or first.package_sha256 is None:
            return _refused_receipt("input_not_structurally_accepted", intake=first)
        session_id = str(uuid.uuid4())
        firmware_id = f"sha256-{first.package_sha256}"
        workspace = self.root / "staging" / session_id
        workspace_created = False
        try:
            root_info = self._prepare_store()
            with _store_lock(self.root):
                sessions, used_entries, used_bytes = _measure_store(
                    self.root, deadline=time.monotonic() + MAX_IO_SECONDS
                )
                if sessions >= MAX_STORE_SESSIONS:
                    raise WorkspaceError("workspace_session_limit")
                try:
                    input_info = Path(os.path.abspath(os.fspath(candidate))).lstat()
                except OSError:
                    raise WorkspaceError("input_changed") from None
                estimated_bytes = (
                    input_info.st_size if first.input_format == "zip" else first.inspected_bytes
                )
                if estimated_bytes > MAX_SNAPSHOT_BYTES:
                    raise WorkspaceError("workspace_snapshot_limit")
                if used_bytes + estimated_bytes + MAX_METADATA_BYTES > MAX_STORE_BYTES:
                    raise WorkspaceError("workspace_store_quota_exceeded")
                deadline = time.monotonic() + MAX_IO_SECONDS
                estimated_entries = _workspace_entry_estimate(
                    Path(os.path.abspath(os.fspath(candidate))),
                    first.input_format,
                    deadline=deadline,
                )
                if used_entries + estimated_entries > MAX_STORE_ENTRIES:
                    raise WorkspaceError("workspace_store_entry_limit")
                try:
                    workspace.mkdir(mode=0o700)
                    workspace_created = True
                except FileExistsError:
                    raise WorkspaceError("workspace_destination_exists") from None
                except OSError:
                    raise WorkspaceError("workspace_create_failed") from None
                workspace_info = _check_directory(workspace)
                marker = _OwnerMarker(
                    workspace_id=session_id,
                    root_device=root_info.st_dev,
                    root_file_id=root_info.st_ino,
                    workspace_device=workspace_info.st_dev,
                    workspace_file_id=workspace_info.st_ino,
                )
                _atomic_json(workspace / "owner.json", marker, replace=False)
                for name in ("inputs", "intermediate", "extraction", "diagnostics"):
                    _ensure_directory(workspace / name)
                initial = _accepted_receipt(
                    first,
                    workspace_id=session_id,
                    state="staging",
                    snapshot_files=0,
                    snapshot_bytes=0,
                    snapshot_verified=False,
                    workspace_owned=True,
                )
                _atomic_json(workspace / "workspace.json", initial, replace=False)
                file_count, snapshot_bytes = _snapshot_input(
                    Path(os.path.abspath(os.fspath(candidate))),
                    first,
                    workspace,
                    deadline=deadline,
                )
                snapshot = inspect_firmware(_workspace_snapshot_path(workspace, initial))
                after = inspect_firmware(candidate)
                if not _copy_identity_matches(first, snapshot) or not _same_intake(first, after):
                    raise WorkspaceError("input_changed")
                staged = _accepted_receipt(
                    first,
                    workspace_id=session_id,
                    state="staging",
                    snapshot_files=file_count,
                    snapshot_bytes=snapshot_bytes,
                    snapshot_verified=True,
                    workspace_owned=True,
                    quota_verified=True,
                )
                _atomic_json(workspace / "workspace.json", staged, replace=True)
                self._measure_workspace(workspace)
                return staged
        except KeyboardInterrupt:
            code = "interrupted"
            if workspace_created:
                return self._quarantine_created(workspace, session_id, first, firmware_id, code)
            return _refused_receipt(code, intake=first)
        except (WorkspaceError, OSError, ValueError, RuntimeError):
            code = "input_changed"
            error = sys.exc_info()[1]
            if error is not None:
                code = _identity_code(error)
            if not workspace_created:
                return _refused_receipt(code, intake=first)
            quarantined = self._quarantine_created(workspace, session_id, first, firmware_id, code)
            return quarantined

    def finalize(self, session_id: str) -> WorkspaceReceipt:
        """Revalidate the private snapshot and atomically publish a ready session."""
        try:
            session_id = _check_id(session_id)
            self._prepare_store()
            with _store_lock(self.root):
                state, staging, staging_info, receipt = _owned_workspace(self.root, session_id)
                if state != "staging" or receipt.state != "staging":
                    raise WorkspaceError("workspace_state_mismatch")
                _verify_snapshot(staging, receipt)
                self._measure_workspace(staging)
                publishing = receipt.model_copy(update={"state": "publishing"})
                _atomic_json(staging / "workspace.json", publishing, replace=True)
                target_root = self.root / "workspaces" / str(receipt.firmware_id)
                _ensure_directory(target_root)
                if target_root.stat().st_dev != staging_info.st_dev:
                    raise WorkspaceError("workspace_cross_device_publish")
                target = target_root / session_id
                _safe_components(target_root)
                if os.path.lexists(target):
                    raise WorkspaceError("workspace_destination_exists")
                _publish_no_replace(staging, target)
                _sync_directory(target_root)
                finalized = publishing.model_copy(update={"state": "finalized"})
                _atomic_json(target / "workspace.json", finalized, replace=True)
                self._measure_workspace(target)
                return finalized
        except KeyboardInterrupt:
            return self._quarantine_existing(session_id, "interrupted")
        except (WorkspaceError, OSError, ValueError, RuntimeError):
            error = sys.exc_info()[1]
            code = _identity_code(error) if error is not None else "workspace_finalize_failed"
            return self._quarantine_existing(session_id, code)

    def create(self, candidate: Path) -> WorkspaceReceipt:
        """Stage and finalize one input as a convenience operation."""
        staged = self.stage(candidate)
        if staged.operation_status == "refused" or staged.workspace_id is None:
            return staged
        if staged.state != "staging":
            return staged
        return self.finalize(staged.workspace_id)

    def verify(self, session_id: str) -> WorkspaceReceipt:
        """Recompute the input identity before any future workspace consumer uses it."""
        try:
            session_id = _check_id(session_id)
            self._prepare_store()
            with _store_lock(self.root):
                state, workspace, _, receipt = _owned_workspace(self.root, session_id)
                if state not in {"staging", "finalized"}:
                    raise WorkspaceError("workspace_state_mismatch")
                observed = _verify_snapshot(workspace, receipt)
                self._measure_workspace(workspace)
                return _accepted_receipt(
                    observed,
                    workspace_id=session_id,
                    state="staging" if state == "staging" else "finalized",
                    snapshot_files=receipt.snapshot_files,
                    snapshot_bytes=receipt.snapshot_bytes,
                    snapshot_verified=True,
                    workspace_owned=True,
                    quota_verified=True,
                )
        except KeyboardInterrupt:
            return self._quarantine_existing(session_id, "interrupted")
        except (WorkspaceError, OSError, ValueError, RuntimeError):
            error = sys.exc_info()[1]
            code = _identity_code(error) if error is not None else "workspace_verify_failed"
            return self._quarantine_existing(session_id, code)

    def _persist_synthetic_receipt(
        self,
        receipt_path: Path,
        workspace: Path,
        receipt: SyntheticExtractionReceipt,
    ) -> SyntheticExtractionReceipt:
        """Persist a receipt until its measured session/store byte counts stabilize."""
        candidate = receipt
        for _attempt in range(5):
            payload = (candidate.model_dump_json(indent=2) + "\n").encode("utf-8")
            if len(payload) > SYNTHETIC_RECEIPT_RESERVE_BYTES:
                raise WorkspaceError("synthetic_receipt_limit")
            _atomic_json(receipt_path, candidate, replace=os.path.lexists(receipt_path))
            session_entries, session_bytes = self._measure_workspace(workspace)
            _sessions, store_entries, store_bytes = _measure_store(
                self.root, deadline=time.monotonic() + MAX_IO_SECONDS
            )
            updated = candidate.model_copy(
                update={
                    "session_bytes_after": session_bytes,
                    "store_bytes_after": store_bytes,
                    "session_entries_after": session_entries,
                    "store_entries_after": store_entries,
                }
            )
            if updated == candidate:
                return candidate
            candidate = updated
        raise WorkspaceError("synthetic_quota_measurement_unstable")

    def _retain_synthetic_incomplete(
        self,
        *,
        artifact: Path,
        workspace: Path,
        operation_id: str,
        receipt: SyntheticExtractionReceipt,
        failure_code: str,
    ) -> SyntheticExtractionReceipt:
        """Retain observed partial outputs under an explicit incomplete identity."""
        output_manifest = receipt.output_manifest
        outputs_root = artifact / "outputs"
        try:
            output_manifest = _observe_synthetic_output_tree(
                outputs_root,
                expected_device=_check_directory(self.root).st_dev,
            )
        except (WorkspaceError, OSError, ValueError, RuntimeError):
            pass
        incomplete = receipt.model_copy(
            update={
                "operation_status": "refused",
                "state": "incomplete",
                "publication_status": "not_published",
                "failure_code": failure_code,
                "output_manifest": output_manifest,
                "output_file_count": len(output_manifest),
                "output_bytes": sum(item.size for item in output_manifest),
                "conditions": _synthetic_conditions(
                    ownership="verified",
                    snapshot="verified",
                    fixture="verified",
                    output_paths="verified",
                    output="unverified",
                    quota="unverified",
                    publication="rejected",
                ),
            }
        )
        receipt_path = artifact / "operation.json"
        try:
            incomplete = self._persist_synthetic_receipt(receipt_path, workspace, incomplete)
        except (WorkspaceError, OSError, ValueError, RuntimeError):
            # The directory name remains an explicit incomplete marker if receipt
            # repair cannot finish, including after a hard process interruption.
            pass
        destination = artifact.parent / f"incomplete-{operation_id}"
        try:
            _safe_components(artifact.parent)
            if os.path.lexists(artifact) and not os.path.lexists(destination):
                _publish_no_replace(artifact, destination)
        except (WorkspaceError, OSError, ValueError, RuntimeError):
            pass
        return incomplete

    def extract_synthetic(self, session_id: str) -> SyntheticExtractionReceipt:
        """Materialize fixed synthetic files for the one content-pinned test fixture."""
        normalized_id: str | None = None
        owned_receipt: WorkspaceReceipt | None = None
        snapshot_verified = False
        fixture_status = "unverified"
        output_path_status = "unverified"
        quota_status = "unverified"
        session_entries_before: int | None = None
        session_bytes_before: int | None = None
        store_entries_before: int | None = None
        store_bytes_before: int | None = None
        expected_manifest: list[SyntheticOutputIdentity] | None = None
        workspace: Path | None = None
        operation_id: str | None = None
        artifact: Path | None = None
        active_receipt: SyntheticExtractionReceipt | None = None
        try:
            normalized_id = _check_id(session_id)
            self._prepare_store()
            with _store_lock(self.root):
                state, workspace, workspace_info, owned_receipt = _owned_workspace(
                    self.root, normalized_id
                )
                if state != "finalized" or owned_receipt.state != "finalized":
                    raise WorkspaceError("workspace_not_finalized")
                observed = _verify_snapshot(workspace, owned_receipt)
                snapshot_verified = True
                input_digest = observed.package_sha256
                if input_digest is None:
                    raise WorkspaceError("workspace_snapshot_identity_missing")
                sessions, store_entries, store_bytes = _measure_store(
                    self.root, deadline=time.monotonic() + MAX_IO_SECONDS
                )
                session_entries, session_bytes = self._measure_workspace(workspace)
                store_entries_before = store_entries
                store_bytes_before = store_bytes
                session_entries_before = session_entries
                session_bytes_before = session_bytes
                quota_status = "verified"
                if workspace_info.st_dev != _check_directory(self.root).st_dev:
                    raise WorkspaceError("workspace_mount_boundary")
                if input_digest != SYNTHETIC_FIXTURE_PACKAGE_SHA256:
                    fixture_status = "rejected"
                    return _synthetic_refusal(
                        "synthetic_fixture_identity_mismatch",
                        workspace_id=normalized_id,
                        firmware_id=owned_receipt.firmware_id,
                        input_digest=input_digest,
                        session_bytes_before=session_bytes,
                        session_bytes_after=session_bytes,
                        store_bytes_before=store_bytes,
                        store_bytes_after=store_bytes,
                        session_entries_before=session_entries,
                        session_entries_after=session_entries,
                        store_entries_before=store_entries,
                        store_entries_after=store_entries,
                        ownership="verified",
                        snapshot="verified",
                        fixture=fixture_status,
                        quota=quota_status,
                    )
                fixture_status = "verified"
                output_files = _synthetic_output_files(input_digest)
                try:
                    output_file_count, output_bytes = _validate_synthetic_output_files(output_files)
                except WorkspaceError as error:
                    if error.code in {
                        "unsafe_synthetic_output_path",
                        "synthetic_output_path_collision",
                    }:
                        output_path_status = "rejected"
                    raise
                output_path_status = "verified"
                expected_manifest = _synthetic_manifest(output_files)
                extraction_root = workspace / "extraction"
                _safe_components(extraction_root)
                extraction_info = _check_directory(extraction_root)
                if extraction_info.st_dev != workspace_info.st_dev:
                    raise WorkspaceError("workspace_mount_boundary")
                final_output = extraction_root / "synthetic-v1"
                entries = _scan_entries(
                    extraction_root,
                    maximum=MAX_ENTRIES + 16,
                    code="workspace_enumeration_failed",
                )
                if any(entry.name == "synthetic-v1" for entry in entries):
                    raise WorkspaceError("synthetic_output_already_exists")
                if any(entry.name.startswith(("staging-", "incomplete-")) for entry in entries):
                    raise WorkspaceError("synthetic_output_incomplete_exists")
                if entries:
                    raise WorkspaceError("synthetic_output_area_not_empty")
                staging_entry_count = (
                    1
                    + 1
                    + output_file_count
                    + 1
                    + 1
                    + len(
                        {
                            "/".join(name.split("/")[:index])
                            for name, _content in output_files
                            for index in range(1, len(name.split("/")))
                        }
                    )
                )
                reserved_bytes = output_bytes + 2 * SYNTHETIC_RECEIPT_RESERVE_BYTES
                if session_bytes + reserved_bytes > MAX_SESSION_BYTES:
                    quota_status = "rejected"
                    raise WorkspaceError("workspace_session_quota_exceeded")
                if store_bytes + reserved_bytes > MAX_STORE_BYTES:
                    quota_status = "rejected"
                    raise WorkspaceError("workspace_store_quota_exceeded")
                if session_entries + staging_entry_count > MAX_ENTRIES + 16:
                    quota_status = "rejected"
                    raise WorkspaceError("workspace_entry_limit")
                if store_entries + staging_entry_count > MAX_STORE_ENTRIES:
                    quota_status = "rejected"
                    raise WorkspaceError("workspace_store_entry_limit")

                operation_id = str(uuid.uuid4())
                artifact = extraction_root / f"staging-{operation_id}"
                artifact.mkdir(mode=0o700)
                initial_receipt = _synthetic_refusal(
                    "operation_incomplete",
                    workspace_id=normalized_id,
                    firmware_id=owned_receipt.firmware_id,
                    input_digest=input_digest,
                    operation_id=operation_id,
                    expected_output_manifest=expected_manifest,
                    session_bytes_before=session_bytes,
                    store_bytes_before=store_bytes,
                    session_entries_before=session_entries,
                    store_entries_before=store_entries,
                    ownership="verified",
                    snapshot="verified",
                    fixture="verified",
                    output_paths="verified",
                    quota="verified",
                    publication="unverified",
                    state="incomplete",
                )
                active_receipt = initial_receipt
                try:
                    _atomic_json(artifact / "operation.json", initial_receipt, replace=False)
                    outputs_root = artifact / "outputs"
                    _ensure_directory(outputs_root)
                    observed_outputs: list[SyntheticOutputIdentity] = []
                    deadline = time.monotonic() + MAX_IO_SECONDS
                    for index, (relative, content) in enumerate(output_files):
                        if time.monotonic() > deadline:
                            raise WorkspaceError("workspace_time_limit")
                        current_session_entries, current_session_bytes = self._measure_workspace(
                            workspace
                        )
                        _current_sessions, current_store_entries, current_store_bytes = (
                            _measure_store(self.root, deadline=time.monotonic() + MAX_IO_SECONDS)
                        )
                        remaining_bytes = sum(
                            len(remaining_content)
                            for _remaining_name, remaining_content in output_files[index:]
                        )
                        remaining_files = len(output_files) - index
                        if (
                            current_session_bytes
                            + remaining_bytes
                            + SYNTHETIC_RECEIPT_RESERVE_BYTES
                            > MAX_SESSION_BYTES
                        ):
                            quota_status = "rejected"
                            raise WorkspaceError("workspace_session_quota_exceeded")
                        if (
                            current_store_bytes + remaining_bytes + SYNTHETIC_RECEIPT_RESERVE_BYTES
                            > MAX_STORE_BYTES
                        ):
                            quota_status = "rejected"
                            raise WorkspaceError("workspace_store_quota_exceeded")
                        if current_session_entries + remaining_files + 1 > MAX_ENTRIES + 16:
                            quota_status = "rejected"
                            raise WorkspaceError("workspace_entry_limit")
                        if current_store_entries + remaining_files + 1 > MAX_STORE_ENTRIES:
                            quota_status = "rejected"
                            raise WorkspaceError("workspace_store_entry_limit")
                        observed_outputs.append(
                            _write_synthetic_output(
                                outputs_root,
                                relative,
                                content,
                                expected_device=workspace_info.st_dev,
                            )
                        )
                        active_receipt = active_receipt.model_copy(
                            update={
                                "output_manifest": list(observed_outputs),
                                "output_file_count": len(observed_outputs),
                                "output_bytes": sum(item.size for item in observed_outputs),
                            }
                        )
                        active_receipt = self._persist_synthetic_receipt(
                            artifact / "operation.json", workspace, active_receipt
                        )
                    verified_manifest = _verify_synthetic_output_tree(
                        outputs_root,
                        output_files,
                        expected_device=workspace_info.st_dev,
                    )
                    if verified_manifest != expected_manifest:
                        raise WorkspaceError("synthetic_output_digest_mismatch")
                    active_receipt = active_receipt.model_copy(
                        update={
                            "output_manifest": verified_manifest,
                            "output_file_count": len(verified_manifest),
                            "output_bytes": sum(item.size for item in verified_manifest),
                            "conditions": _synthetic_conditions(
                                ownership="verified",
                                snapshot="verified",
                                fixture="verified",
                                output_paths="verified",
                                output="verified",
                                quota="verified",
                                publication="unverified",
                            ),
                        }
                    )
                    active_receipt = self._persist_synthetic_receipt(
                        artifact / "operation.json", workspace, active_receipt
                    )
                    _publish_no_replace(artifact, final_output)
                    artifact = final_output
                    published = active_receipt.model_copy(
                        update={
                            "operation_status": "accepted",
                            "state": "published",
                            "publication_status": "published",
                            "failure_code": None,
                            "conditions": _synthetic_conditions(
                                ownership="verified",
                                snapshot="verified",
                                fixture="verified",
                                output_paths="verified",
                                output="verified",
                                quota="verified",
                                publication="verified",
                            ),
                        }
                    )
                    published = self._persist_synthetic_receipt(
                        final_output / "operation.json", workspace, published
                    )
                    return published
                except KeyboardInterrupt:
                    return self._retain_synthetic_incomplete(
                        artifact=artifact,
                        workspace=workspace,
                        operation_id=operation_id,
                        receipt=active_receipt,
                        failure_code="operation_interrupted",
                    )
                except (WorkspaceError, OSError, ValueError, RuntimeError):
                    error = sys.exc_info()[1]
                    failure_code = (
                        error.code
                        if isinstance(error, WorkspaceError)
                        else "synthetic_output_write_failed"
                    )
                    return self._retain_synthetic_incomplete(
                        artifact=artifact,
                        workspace=workspace,
                        operation_id=operation_id,
                        receipt=active_receipt,
                        failure_code=failure_code,
                    )
        except KeyboardInterrupt:
            return _synthetic_refusal(
                "operation_interrupted",
                workspace_id=normalized_id,
                ownership="verified" if owned_receipt is not None else "unverified",
                snapshot="verified" if snapshot_verified else "unverified",
                fixture=fixture_status,
                output_paths=output_path_status,
                quota=quota_status,
                expected_output_manifest=expected_manifest,
                session_bytes_before=session_bytes_before,
                session_bytes_after=session_bytes_before,
                store_bytes_before=store_bytes_before,
                store_bytes_after=store_bytes_before,
                session_entries_before=session_entries_before,
                session_entries_after=session_entries_before,
                store_entries_before=store_entries_before,
                store_entries_after=store_entries_before,
            )
        except (WorkspaceError, OSError, ValueError, RuntimeError):
            error = sys.exc_info()[1]
            code = (
                error.code if isinstance(error, WorkspaceError) else "synthetic_extraction_refused"
            )
            return _synthetic_refusal(
                code,
                workspace_id=normalized_id,
                firmware_id=owned_receipt.firmware_id if owned_receipt is not None else None,
                input_digest=owned_receipt.input_digest if owned_receipt is not None else None,
                ownership="verified" if owned_receipt is not None else "unverified",
                snapshot="verified" if snapshot_verified else "unverified",
                fixture=fixture_status,
                output_paths=(
                    "rejected"
                    if code in {"unsafe_synthetic_output_path", "synthetic_output_path_collision"}
                    else output_path_status
                ),
                quota="rejected" if code in _QUOTA_FAILURE_CODES else quota_status,
                expected_output_manifest=expected_manifest,
                session_bytes_before=session_bytes_before,
                session_bytes_after=session_bytes_before,
                store_bytes_before=store_bytes_before,
                store_bytes_after=store_bytes_before,
                session_entries_before=session_entries_before,
                session_entries_after=session_entries_before,
                store_entries_before=store_entries_before,
                store_entries_after=store_entries_before,
            )

    def verify_synthetic_extraction(self, session_id: str) -> SyntheticExtractionReceipt:
        """Independently recheck a published synthetic output receipt and every file hash."""
        normalized_id: str | None = None
        owned_receipt: WorkspaceReceipt | None = None
        persisted_receipt: SyntheticExtractionReceipt | None = None
        published_output_exists = False
        quota_measured = False
        try:
            normalized_id = _check_id(session_id)
            self._prepare_store()
            with _store_lock(self.root):
                state, workspace, workspace_info, owned_receipt = _owned_workspace(
                    self.root, normalized_id
                )
                if state != "finalized" or owned_receipt.state != "finalized":
                    raise WorkspaceError("workspace_not_finalized")
                observed = _verify_snapshot(workspace, owned_receipt)
                input_digest = observed.package_sha256
                if input_digest != SYNTHETIC_FIXTURE_PACKAGE_SHA256:
                    return _synthetic_refusal(
                        "synthetic_fixture_identity_mismatch",
                        workspace_id=normalized_id,
                        firmware_id=owned_receipt.firmware_id,
                        input_digest=input_digest,
                        ownership="verified",
                        snapshot="verified",
                        fixture="rejected",
                    )
                _session_entries, _session_bytes = self._measure_workspace(workspace)
                _sessions, _store_entries, _store_bytes = _measure_store(
                    self.root, deadline=time.monotonic() + MAX_IO_SECONDS
                )
                quota_measured = True
                extraction_root = workspace / "extraction"
                _safe_components(extraction_root)
                final_output = extraction_root / "synthetic-v1"
                try:
                    final_info = final_output.lstat()
                except FileNotFoundError:
                    entries = _scan_entries(
                        extraction_root,
                        maximum=MAX_ENTRIES + 16,
                        code="workspace_enumeration_failed",
                    )
                    incomplete_entry = next(
                        (
                            entry
                            for entry in entries
                            if entry.name.startswith(("staging-", "incomplete-"))
                        ),
                        None,
                    )
                    if incomplete_entry is not None:
                        suffix = incomplete_entry.name.removeprefix("staging-").removeprefix(
                            "incomplete-"
                        )
                        try:
                            operation_id = _check_id(suffix)
                        except WorkspaceError:
                            raise WorkspaceError("synthetic_output_incomplete_exists") from None
                        try:
                            incomplete = SyntheticExtractionReceipt.model_validate_json(
                                _read_regular(
                                    Path(incomplete_entry.path) / "operation.json",
                                    maximum=SYNTHETIC_RECEIPT_RESERVE_BYTES,
                                )
                            )
                        except (WorkspaceError, ValidationError):
                            return _synthetic_refusal(
                                "synthetic_output_incomplete_exists",
                                workspace_id=normalized_id,
                                firmware_id=owned_receipt.firmware_id,
                                input_digest=input_digest,
                                operation_id=operation_id,
                                ownership="verified",
                                snapshot="verified",
                                fixture="verified",
                                quota="verified",
                                output="unverified",
                                publication="unverified",
                                state="incomplete",
                            )
                        expected_files = _synthetic_output_files(input_digest)
                        expected_manifest = _synthetic_manifest(expected_files)
                        if (
                            incomplete.state != "incomplete"
                            or incomplete.operation_status != "refused"
                            or incomplete.publication_status != "not_published"
                            or incomplete.operation_id != operation_id
                            or incomplete.workspace_id != normalized_id
                            or incomplete.firmware_id != owned_receipt.firmware_id
                            or incomplete.input_digest != input_digest
                            or incomplete.operation != SYNTHETIC_EXTRACTION_OPERATION
                            or incomplete.expected_output_manifest != expected_manifest
                        ):
                            raise WorkspaceError("synthetic_output_incomplete_exists") from None
                        return incomplete.model_copy(
                            update={
                                "conditions": _synthetic_conditions(
                                    ownership="verified",
                                    snapshot="verified",
                                    fixture="verified",
                                    output_paths="verified",
                                    output="unverified",
                                    quota="verified",
                                    publication="unverified",
                                )
                            }
                        )
                    raise WorkspaceError("synthetic_output_not_found") from None
                except OSError:
                    raise WorkspaceError("synthetic_output_unavailable") from None
                if (
                    _linked(final_info)
                    or not stat.S_ISDIR(final_info.st_mode)
                    or final_info.st_dev != workspace_info.st_dev
                ):
                    raise WorkspaceError("unsafe_synthetic_output_directory")
                published_output_exists = True
                receipt_path = final_output / "operation.json"
                try:
                    persisted_receipt = SyntheticExtractionReceipt.model_validate_json(
                        _read_regular(receipt_path, maximum=SYNTHETIC_RECEIPT_RESERVE_BYTES)
                    )
                except ValidationError:
                    raise WorkspaceError("synthetic_receipt_invalid") from None
                if (
                    persisted_receipt.operation_status != "accepted"
                    or persisted_receipt.state != "published"
                    or persisted_receipt.publication_status != "published"
                    or persisted_receipt.failure_code is not None
                    or persisted_receipt.operation_id is None
                    or persisted_receipt.workspace_id != normalized_id
                    or persisted_receipt.firmware_id != owned_receipt.firmware_id
                    or persisted_receipt.input_digest != input_digest
                ):
                    return _synthetic_refusal(
                        "synthetic_output_incomplete_exists",
                        workspace_id=normalized_id,
                        firmware_id=owned_receipt.firmware_id,
                        input_digest=input_digest,
                        operation_id=persisted_receipt.operation_id,
                        expected_output_manifest=persisted_receipt.expected_output_manifest,
                        output_manifest=persisted_receipt.output_manifest,
                        ownership="verified",
                        snapshot="verified",
                        fixture="verified",
                        quota="verified",
                        publication="unverified",
                        state="incomplete",
                    )
                output_files = _synthetic_output_files(input_digest)
                _validate_synthetic_output_files(output_files)
                expected_manifest = _synthetic_manifest(output_files)
                observed_manifest = _verify_synthetic_output_tree(
                    final_output / "outputs",
                    output_files,
                    expected_device=workspace_info.st_dev,
                )
                if (
                    persisted_receipt.operation != SYNTHETIC_EXTRACTION_OPERATION
                    or persisted_receipt.expected_output_manifest != expected_manifest
                    or persisted_receipt.output_manifest != observed_manifest
                    or persisted_receipt.output_file_count != len(observed_manifest)
                    or persisted_receipt.output_bytes
                    != sum(item.size for item in observed_manifest)
                ):
                    raise WorkspaceError("synthetic_output_digest_mismatch")
                return persisted_receipt.model_copy(
                    update={
                        "conditions": _synthetic_conditions(
                            ownership="verified",
                            snapshot="verified",
                            fixture="verified",
                            output_paths="verified",
                            output="verified",
                            quota="verified",
                            publication="verified",
                        )
                    }
                )
        except KeyboardInterrupt:
            return _synthetic_refusal(
                "operation_interrupted",
                workspace_id=normalized_id,
                ownership="verified" if owned_receipt is not None else "unverified",
                snapshot="unverified",
            )
        except (WorkspaceError, OSError, ValueError, RuntimeError):
            error = sys.exc_info()[1]
            code = (
                error.code
                if isinstance(error, WorkspaceError)
                else "synthetic_verification_refused"
            )
            return _synthetic_refusal(
                code,
                workspace_id=normalized_id,
                firmware_id=owned_receipt.firmware_id if owned_receipt is not None else None,
                input_digest=owned_receipt.input_digest if owned_receipt is not None else None,
                operation_id=(
                    persisted_receipt.operation_id if persisted_receipt is not None else None
                ),
                expected_output_manifest=(
                    persisted_receipt.expected_output_manifest
                    if persisted_receipt is not None
                    else None
                ),
                output_manifest=(
                    persisted_receipt.output_manifest if persisted_receipt is not None else None
                ),
                ownership="verified" if owned_receipt is not None else "unverified",
                snapshot="verified" if code != "workspace_snapshot_mismatch" else "rejected",
                fixture="verified" if owned_receipt is not None else "unverified",
                output="rejected" if published_output_exists else "unverified",
                output_paths="verified" if published_output_exists else "unverified",
                quota=(
                    "rejected"
                    if code in _QUOTA_FAILURE_CODES
                    else "verified"
                    if quota_measured
                    else "unverified"
                ),
                publication="verified" if published_output_exists else "unverified",
                state="published" if published_output_exists else "refused",
                publication_status="published" if published_output_exists else "not_published",
            )

    def quarantine(self, session_id: str, reason: str = "operator_review") -> WorkspaceReceipt:
        """Move an owned session to retained quarantine without deleting its bytes."""
        try:
            session_id = _check_id(session_id)
            if reason not in {
                "operator_review",
                "input_changed",
                "interrupted",
                "workspace_corrupt",
                "finalization_incomplete",
            }:
                raise WorkspaceError("quarantine_reason_unsupported")
            self._prepare_store()
            with _store_lock(self.root):
                state, workspace, workspace_info, receipt = _owned_workspace(self.root, session_id)
                if state == "quarantined":
                    raise WorkspaceError("workspace_already_quarantined")
                destination = self.root / "quarantine" / session_id
                if os.path.lexists(destination):
                    raise WorkspaceError("workspace_destination_exists")
                _safe_components(workspace.parent)
                _safe_components(destination.parent)
                if workspace_info.st_dev != destination.parent.stat().st_dev:
                    raise WorkspaceError("workspace_cross_device_publish")
                _publish_no_replace(workspace, destination)
                quarantined = receipt.model_copy(
                    update={
                        "operation_status": "refused",
                        "state": "quarantined",
                        "conditions": [
                            Condition(
                                check="workspace_lifecycle",
                                status="verified",
                                code=f"quarantined_{reason}",
                            ),
                            *_workspace_conditions(
                                snapshot_verified=False,
                                state="quarantined",
                                workspace_owned=True,
                            ),
                        ],
                    }
                )
                _atomic_json(destination / "workspace.json", quarantined, replace=True)
                return quarantined.model_copy(
                    update={
                        "conditions": [
                            Condition(
                                check="workspace_lifecycle",
                                status="verified",
                                code=f"quarantined_{reason}",
                            ),
                            *_workspace_conditions(
                                snapshot_verified=False,
                                state="quarantined",
                                workspace_owned=True,
                            ),
                        ]
                    }
                )
        except KeyboardInterrupt:
            return self._quarantine_existing(session_id, "interrupted")
        except (WorkspaceError, OSError, ValueError, RuntimeError):
            error = sys.exc_info()[1]
            code = _identity_code(error) if error is not None else "workspace_quarantine_failed"
            return _refused_receipt(code)

    def cleanup(self, session_id: str) -> WorkspaceReceipt:
        """Remove only an explicitly selected, owned, empty staging skeleton."""
        try:
            session_id = _check_id(session_id)
            self._prepare_store()
            with _store_lock(self.root):
                state, workspace, workspace_info, receipt = _owned_workspace(self.root, session_id)
                if state != "staging" or receipt.state != "staging":
                    raise WorkspaceError("cleanup_only_empty_staging")
                self._measure_workspace(workspace)
                if not _empty_staging_workspace(workspace):
                    raise WorkspaceError("staging_contains_retained_input")
                _remove_empty_staging(workspace, workspace_info)
                return receipt.model_copy(
                    update={
                        "state": "cleaned",
                        "conditions": [
                            Condition(
                                check="workspace_cleanup",
                                status="verified",
                                code="empty_owned_staging_removed",
                            ),
                            *_workspace_conditions(
                                snapshot_verified=False,
                                state="cleaned",
                                workspace_owned=True,
                                quota_verified=True,
                            ),
                        ],
                    }
                )
        except (WorkspaceError, OSError, ValueError, RuntimeError):
            error = sys.exc_info()[1]
            code = _identity_code(error) if error is not None else "workspace_cleanup_refused"
            return _refused_receipt(code)

    def list(self) -> builtins.list[WorkspaceReceipt]:
        """List bounded pathless session receipts without reading firmware payloads."""
        try:
            self._prepare_store()
            with _store_lock(self.root):
                _measure_store(self.root, deadline=time.monotonic() + MAX_IO_SECONDS)
                result: list[WorkspaceReceipt] = []
                for category in _ROOT_LAYOUT:
                    base = self.root / category
                    for entry in _scan_entries(
                        base, maximum=MAX_STORE_SESSIONS, code="workspace_enumeration_failed"
                    ):
                        if category == "workspaces":
                            package_path = Path(entry.path)
                            for session in _scan_entries(
                                package_path,
                                maximum=MAX_STORE_SESSIONS,
                                code="workspace_enumeration_failed",
                            ):
                                result.append(_load_receipt(Path(session.path)))
                        else:
                            result.append(_load_receipt(Path(entry.path)))
                return result
        except (WorkspaceError, OSError, ValueError, RuntimeError):
            raise WorkspaceError("workspace_list_refused") from None

    def _measure_workspace(self, workspace: Path) -> tuple[int, int]:
        root_info = _check_directory(self.root)
        return _safe_tree(
            workspace,
            deadline=time.monotonic() + MAX_IO_SECONDS,
            max_entries=MAX_ENTRIES + 16,
            max_bytes=MAX_SESSION_BYTES,
            expected_device=root_info.st_dev,
        )

    def _quarantine_created(
        self,
        workspace: Path,
        session_id: str,
        intake: IntakeReceipt,
        firmware_id: str,
        reason: str,
    ) -> WorkspaceReceipt:
        try:
            if not os.path.lexists(workspace):
                return _refused_receipt(reason, intake=intake)
            root_info = _check_directory(self.root)
            workspace_info = _check_directory(workspace)
            marker_path = workspace / "owner.json"
            if os.path.lexists(marker_path):
                _parse_owner(workspace, root_info, workspace_info)
            else:
                marker = _OwnerMarker(
                    workspace_id=session_id,
                    root_device=root_info.st_dev,
                    root_file_id=root_info.st_ino,
                    workspace_device=workspace_info.st_dev,
                    workspace_file_id=workspace_info.st_ino,
                )
                _atomic_json(marker_path, marker, replace=False)
            destination = self.root / "quarantine" / session_id
            if os.path.lexists(destination):
                return _refused_receipt(
                    "workspace_destination_exists",
                    intake=intake,
                    workspace_id=session_id,
                    firmware_id=firmware_id,
                    state="staging",
                )
            if workspace_info.st_dev != destination.parent.stat().st_dev:
                return _refused_receipt(
                    "workspace_cross_device_publish",
                    intake=intake,
                    workspace_id=session_id,
                    firmware_id=firmware_id,
                    state="staging",
                )
            _publish_no_replace(workspace, destination)
            existing = destination / "workspace.json"
            try:
                previous = _load_receipt(destination)
                base = previous.model_copy(
                    update={
                        "operation_status": "refused",
                        "state": "quarantined",
                        "conditions": [
                            Condition(check="workspace", status="rejected", code=reason),
                            *_workspace_conditions(
                                snapshot_verified=False,
                                state="quarantined",
                                workspace_owned=True,
                            ),
                        ],
                    }
                )
                _atomic_json(existing, base, replace=True)
                return base
            except WorkspaceError:
                quarantined = _refused_receipt(
                    reason,
                    intake=intake,
                    workspace_id=session_id,
                    firmware_id=firmware_id,
                    state="quarantined",
                )
                if not os.path.lexists(existing):
                    _atomic_json(existing, quarantined, replace=False)
                return quarantined
        except (WorkspaceError, OSError, ValueError, RuntimeError):
            return _refused_receipt(
                "workspace_quarantine_failed",
                intake=intake,
                workspace_id=session_id,
                firmware_id=firmware_id,
                state="staging",
            )

    def _quarantine_existing(self, session_id: str, reason: str) -> WorkspaceReceipt:
        try:
            session_id = _check_id(session_id)
            if not self.root.exists():
                return _refused_receipt(reason, workspace_id=session_id)
            with _store_lock(self.root):
                locations = _session_locations(self.root, session_id)
                if len(locations) != 1:
                    return _refused_receipt(
                        reason,
                        workspace_id=session_id,
                        state="quarantined" if locations else "none",
                    )
                state, workspace = locations[0]
                if state == "quarantined":
                    root_info = _check_directory(self.root)
                    workspace_info = _check_directory(workspace)
                    marker = _parse_owner(workspace, root_info, workspace_info)
                    if marker.workspace_id != session_id:
                        raise WorkspaceError("workspace_identity_mismatch")
                    try:
                        existing = _load_receipt(workspace)
                        repaired = existing.model_copy(
                            update={
                                "operation_status": "refused",
                                "state": "quarantined",
                                "conditions": [
                                    Condition(check="workspace", status="rejected", code=reason),
                                    *_workspace_conditions(
                                        snapshot_verified=False,
                                        state="quarantined",
                                        workspace_owned=True,
                                    ),
                                ],
                            }
                        )
                        _atomic_json(workspace / "workspace.json", repaired, replace=True)
                        return repaired
                    except WorkspaceError:
                        repaired = _refused_receipt(
                            reason,
                            workspace_id=session_id,
                            state="quarantined",
                            workspace_owned=True,
                        )
                        if not os.path.lexists(workspace / "workspace.json"):
                            _atomic_json(workspace / "workspace.json", repaired, replace=False)
                        return repaired
                root_info = _check_directory(self.root)
                workspace_info = _check_directory(workspace)
                _parse_owner(workspace, root_info, workspace_info)
                destination = self.root / "quarantine" / session_id
                if os.path.lexists(destination):
                    raise WorkspaceError("workspace_destination_exists")
                if workspace_info.st_dev != destination.parent.stat().st_dev:
                    raise WorkspaceError("workspace_cross_device_publish")
                _publish_no_replace(workspace, destination)
                try:
                    previous = _load_receipt(destination)
                    quarantined = previous.model_copy(
                        update={
                            "operation_status": "refused",
                            "state": "quarantined",
                            "conditions": [
                                Condition(check="workspace", status="rejected", code=reason),
                                *_workspace_conditions(
                                    snapshot_verified=False,
                                    state="quarantined",
                                    workspace_owned=True,
                                ),
                            ],
                        }
                    )
                    _atomic_json(destination / "workspace.json", quarantined, replace=True)
                    return quarantined
                except WorkspaceError:
                    return _refused_receipt(reason, workspace_id=session_id, state="quarantined")
        except (WorkspaceError, OSError, ValueError, RuntimeError):
            safe_id = session_id if _SESSION_ID_PATTERN.fullmatch(session_id) else None
            return _refused_receipt(reason, workspace_id=safe_id)
