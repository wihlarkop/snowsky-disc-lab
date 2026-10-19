"""Versioned immutable source identities, separate from cache and runtime adapters."""

import re
from pathlib import Path
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from snowsky_disc_lab.contracts import OutputPath, Sha256, read_yaml_document

type SourceId = Annotated[
    str, StringConstraints(pattern=r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$", max_length=48)
]
type Repository = Annotated[
    str,
    StringConstraints(
        pattern=r"^https://github\.com/[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*\.git$",
        max_length=256,
    ),
]
type GitCommit = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
type Note = Annotated[str, StringConstraints(min_length=1, max_length=512)]
type SourcePath = Annotated[
    str,
    StringConstraints(
        pattern=r"^[A-Za-z0-9_][A-Za-z0-9._-]*(?:/[A-Za-z0-9_][A-Za-z0-9._-]*)*/?$",
        max_length=256,
    ),
]


def _portable_path(value: str) -> str:
    for part in value.rstrip("/").split("/"):
        stem = part.partition(".")[0].upper()
        if (
            part.endswith((".", " "))
            or stem in {"CON", "PRN", "AUX", "NUL"}
            or re.fullmatch(r"(?:COM|LPT)[1-9]", stem)
        ):
            raise ValueError("source paths must be portable file names")
    return value


class _LockModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, validate_by_alias=True, validate_by_name=False
    )


class LicenseRecord(_LockModel):
    path: OutputPath
    sha256: Sha256
    spdx: Note
    scope: Note

    @field_validator("path")
    @classmethod
    def portable_path(cls, value: str) -> str:
        return _portable_path(value)


class SourceProvenance(_LockModel):
    reference: Note
    url: Note
    reviewed_on: Annotated[str, StringConstraints(pattern=r"^\d{4}-\d{2}-\d{2}$")] = Field(
        alias="reviewedOn"
    )
    method: Note


class SourcePin(_LockModel):
    id: SourceId
    repository: Repository
    commit: GitCommit
    include_paths: Annotated[list[SourcePath], Field(min_length=1, max_length=64)] = Field(
        alias="includePaths"
    )
    licenses: Annotated[list[LicenseRecord], Field(min_length=1, max_length=16)]
    provenance: SourceProvenance

    @field_validator("id")
    @classmethod
    def portable_id(cls, value: str) -> str:
        return _portable_path(value)

    @model_validator(mode="after")
    def check_provenance(self) -> "SourcePin":
        if self.provenance.url != f"{self.repository.removesuffix('.git')}/commit/{self.commit}":
            raise ValueError("provenance URL must identify the locked repository and commit")
        if len({item.path for item in self.licenses}) != len(self.licenses):
            raise ValueError("license paths must be unique")
        if len(set(self.include_paths)) != len(self.include_paths):
            raise ValueError("source paths must be unique")
        for path in self.include_paths:
            _portable_path(path)
            if any(part in {".", ".."} for part in path.rstrip("/").split("/")):
                raise ValueError("source paths must not traverse directories")
            if any(
                other != path
                and (
                    other.rstrip("/") == path.rstrip("/")
                    or path.startswith(other.rstrip("/") + "/")
                )
                for other in self.include_paths
            ):
                raise ValueError("source path projections must not overlap")
        if any(
            not any(
                item.path == path or (path.endswith("/") and item.path.startswith(path))
                for path in self.include_paths
            )
            for item in self.licenses
        ):
            raise ValueError("license evidence must be included in the source projection")
        return self


class SourceLock(_LockModel):
    api_version: Literal["lab-upstreams/v1"] = Field(alias="apiVersion")
    kind: Literal["SourceLock"]
    sources: Annotated[list[SourcePin], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def unique_ids(self) -> "SourceLock":
        if len({source.id for source in self.sources}) != len(self.sources):
            raise ValueError("source identifiers must be unique")
        return self


def load_source_lock(path: Path) -> SourceLock:
    data = read_yaml_document(path, "source lock")
    try:
        return SourceLock.model_validate(data)
    except ValidationError as error:
        categories = sorted({item["type"] for item in error.errors(include_input=False)})
        raise ValueError(
            "Invalid source lock: " + ", ".join(categories) + "; see upstream lock schema"
        ) from None
