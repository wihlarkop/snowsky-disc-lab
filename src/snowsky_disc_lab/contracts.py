"""Strict, non-executing manifest contracts for SNOWSKY DISC Lab."""

from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Annotated, Literal

import yaml
from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
)
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode
from yaml.tokens import (
    AliasToken,
    AnchorToken,
    BlockEndToken,
    BlockMappingStartToken,
    BlockSequenceStartToken,
    FlowMappingEndToken,
    FlowMappingStartToken,
    FlowSequenceEndToken,
    FlowSequenceStartToken,
)

MAX_MANIFEST_BYTES = 64 * 1024
MAX_YAML_DEPTH = 64

_NAME_PATTERN = r"^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$"
_REVISION_PATTERN = r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$"
_SHA256_PATTERN = r"^[0-9a-fA-F]{64}$"
_OUTPUT_PATTERN = r"^[A-Za-z0-9_-][A-Za-z0-9._-]*(?:/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$"

type SafeName = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=64, pattern=_NAME_PATTERN),
]
type CommitRevision = Annotated[
    str,
    StringConstraints(strict=True, pattern=_REVISION_PATTERN),
]
type FirmwareVersion = Annotated[
    str,
    StringConstraints(strict=True, strip_whitespace=True, min_length=1, max_length=128),
]
type Sha256 = Annotated[
    str,
    StringConstraints(strict=True, pattern=_SHA256_PATTERN),
]
type OutputPath = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=1024, pattern=_OUTPUT_PATTERN),
]
type RunnerReference = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
type ClaimedFirmware = Annotated[
    str,
    StringConstraints(strict=True, strip_whitespace=True, min_length=1, max_length=128),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_by_alias=True,
        validate_by_name=False,
    )


class UIMetadata(_StrictModel):
    name: SafeName
    upstream: AnyHttpUrl | None = None

    @field_validator("name", mode="after")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        return value.lower()


class UISource(_StrictModel):
    revision: CommitRevision


class UIBuild(_StrictModel):
    preset: Literal["diskos-musl", "disco-musl", "synthetic"]
    output: OutputPath

    @field_validator("output")
    @classmethod
    def reject_ambiguous_output_paths(cls, value: str) -> str:
        windows_path = PureWindowsPath(value)
        posix_parts = PurePosixPath(value).parts
        if (
            "\\" in value
            or ":" in value
            or windows_path.drive
            or windows_path.is_absolute()
            or value.startswith("/")
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or posix_parts != tuple(value.split("/"))
        ):
            raise ValueError("output must be a safe relative POSIX path")
        return value


class UIRuntime(_StrictModel):
    target: Literal["snowsky-disc"]
    architecture: Literal["mipsel"]
    display: Annotated[list[Literal[360]], Field(min_length=2, max_length=2)]
    ipc: Literal["fiio-posix-mqueue"]


class UIClaims(_StrictModel):
    firmware: list[ClaimedFirmware]


class UIManifest(_StrictModel):
    api_version: Literal["lab-ui/v1"] = Field(alias="apiVersion")
    kind: Literal["UI"]
    metadata: UIMetadata
    source: UISource
    build: UIBuild
    runtime: UIRuntime
    claims: UIClaims


class FirmwareIdentity(_StrictModel):
    main: FirmwareVersion
    recovery: FirmwareVersion
    rootfs_sha256: Sha256 | None = Field(default=None, alias="rootfsSha256")
    player_sha256: Sha256 | None = Field(default=None, alias="playerSha256")


class FirmwareRuntime(_StrictModel):
    runner_id: RunnerReference | None = Field(default=None, alias="runnerId")


class FirmwareManifest(_StrictModel):
    api_version: Literal["lab-firmware/v1"] = Field(alias="apiVersion")
    kind: Literal["Firmware"]
    device: Literal["snowsky-disc"]
    firmware: FirmwareIdentity
    runtime: FirmwareRuntime | None = None


type ManifestKind = Literal["ui", "firmware"]


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate keys without formatting them."""

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[object, object]:
        if not isinstance(node, MappingNode):
            raise ConstructorError(None, None, "expected a mapping", node.start_mark)

        self.flatten_mapping(node)
        mapping: dict[object, object] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as error:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "mapping keys must be hashable",
                    key_node.start_mark,
                ) from error
            if duplicate:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "duplicate YAML key",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _safe_field_location(location: tuple[object, ...]) -> str:
    allowed_fields = {
        "apiVersion",
        "kind",
        "metadata",
        "name",
        "upstream",
        "source",
        "revision",
        "build",
        "preset",
        "output",
        "runtime",
        "target",
        "architecture",
        "display",
        "ipc",
        "claims",
        "firmware",
        "device",
        "main",
        "recovery",
        "rootfsSha256",
        "playerSha256",
        "runnerId",
    }
    safe_parts: list[str] = []
    for part in location:
        if isinstance(part, int):
            safe_parts.append(f"[{part}]")
        elif isinstance(part, str) and part in allowed_fields:
            safe_parts.append(part)
        else:
            return "manifest"
    return ".".join(safe_parts) or "manifest"


def _validation_message(kind: ManifestKind, error: ValidationError) -> str:
    details: list[str] = []
    for issue in error.errors(include_url=False, include_context=False, include_input=False)[:8]:
        location = _safe_field_location(tuple(issue["loc"]))
        error_type = str(issue["type"])
        details.append(f"{location}: {error_type}")
    joined = "; ".join(details) if details else "invalid structure"
    return f"Invalid {kind} manifest: {joined}"


def _validate_output_containment(path: Path, manifest: UIManifest) -> None:
    output = manifest.build.output
    try:
        root = path.parent.resolve(strict=False)
        resolved_output = root.joinpath(*PurePosixPath(output).parts).resolve(strict=False)
        resolved_output.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        raise ValueError(
            "Invalid ui manifest: build.output: output path cannot be resolved safely "
            "inside its manifest directory"
        ) from None


def _check_yaml_tokens(text: str, kind: str) -> None:
    depth = 0
    start_tokens = (
        BlockMappingStartToken,
        BlockSequenceStartToken,
        FlowMappingStartToken,
        FlowSequenceStartToken,
    )
    end_tokens = (BlockEndToken, FlowMappingEndToken, FlowSequenceEndToken)
    for token in yaml.scan(text, Loader=_UniqueKeySafeLoader):
        if isinstance(token, (AnchorToken, AliasToken)):
            raise ValueError(f"Invalid {kind} manifest: YAML anchors and aliases are not supported")
        if isinstance(token, start_tokens):
            depth += 1
            if depth > MAX_YAML_DEPTH:
                raise ValueError(
                    f"Invalid {kind} manifest: YAML nesting exceeds the "
                    f"{MAX_YAML_DEPTH}-level limit"
                )
        elif isinstance(token, end_tokens):
            depth = max(0, depth - 1)


def _read_bounded_manifest(path: Path, kind: str) -> bytes:
    file_status = path.stat()
    if not stat.S_ISREG(file_status.st_mode):
        raise ValueError(f"Invalid {kind} manifest path: input must be a regular file")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"Invalid {kind} manifest path: input must be a regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            return stream.read(MAX_MANIFEST_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def read_yaml_document(path: Path, kind: str) -> object:
    """Read bounded, regular-file YAML data with no tags, aliases or duplicate keys."""
    raw = _read_bounded_manifest(path, kind)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError(
            f"Invalid {kind} manifest: input exceeds the {MAX_MANIFEST_BYTES}-byte size limit"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(f"Invalid {kind} manifest: input must be valid UTF-8") from None

    try:
        _check_yaml_tokens(text, kind)
        data = yaml.load(text, Loader=_UniqueKeySafeLoader)
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        position = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        problem = getattr(error, "problem", None)
        if problem == "duplicate YAML key":
            reason = "duplicate YAML key"
        else:
            reason = "invalid YAML syntax"
        raise ValueError(f"Invalid {kind} manifest: {reason}{position}") from None
    except RecursionError:
        raise ValueError(
            f"Invalid {kind} manifest: YAML nesting exceeds the supported limit"
        ) from None

    return data


def load_manifest(path: Path, kind: ManifestKind) -> UIManifest | FirmwareManifest:
    """Load and validate a bounded YAML manifest without reading its artifacts."""
    if kind not in ("ui", "firmware"):
        raise ValueError("Manifest kind must be 'ui' or 'firmware'")
    manifest_path = Path(path)
    data = read_yaml_document(manifest_path, kind)

    model_type: type[UIManifest] | type[FirmwareManifest]
    if kind == "ui":
        model_type = UIManifest
    else:
        model_type = FirmwareManifest
    try:
        manifest = model_type.model_validate(data)
    except ValidationError as error:
        raise ValueError(_validation_message(kind, error)) from None
    except RecursionError:
        raise ValueError(
            f"Invalid {kind} manifest: YAML nesting exceeds the supported limit"
        ) from None

    if isinstance(manifest, UIManifest):
        _validate_output_containment(manifest_path, manifest)
    return manifest


def schema_documents() -> dict[str, dict[str, object]]:
    """Return the generated public JSON Schemas keyed by their checked-in filenames."""
    return {
        "lab-ui-v1.schema.json": UIManifest.model_json_schema(by_alias=True),
        "lab-firmware-v1.schema.json": FirmwareManifest.model_json_schema(by_alias=True),
    }
