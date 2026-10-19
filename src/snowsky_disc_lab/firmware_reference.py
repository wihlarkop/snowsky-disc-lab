"""Read the pinned, data-only V2.57 firmware intake reference."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from importlib.resources import files
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

type Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
REFERENCE_SHA256 = "5051401086f147476f2cf841b713fcccb518c777ad5be86c2c2b7c3b086ae1c5"
_BINARY_PATHS = frozenset(
    {
        "usr/bin/mq_player",
        "usr/bin/mq_ui",
        "bin/busybox",
        "lib/ld-2.29.so",
        "lib/libc-2.29.so",
        "usr/lib/libtinyalsa.so.1.1.1",
    }
)


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
    )


class UpstreamRepository(_FrozenModel):
    repository: Literal["https://github.com/eudj1n/snowsky-disc-qemu.git"]
    commit: Literal["85ab00deb08ac112066377fd8083cc8727ed859a"]


class ProfileSourceIdentity(_FrozenModel):
    path: Literal["firmware/v2.57.json"]
    git_blob: Literal["6ff5fb7c2371fac8b5f4cddc12dc0e6d47b9d3ca"] = Field(alias="gitBlob")
    sha256: Literal["e0bb2613eff334e3550f41a992b4b10c0bff151ddcb0c64d128eef77ec6606a9"]


class ParserSourceIdentity(_FrozenModel):
    path: Literal["firmware/tools/firmware_inventory.py"]
    git_blob: Literal["c59e4b27709b1c08a638ca95c6d34ec701c58245"] = Field(alias="gitBlob")
    sha256: Literal["da3d4f9582f9699b030ed86c4ccc607213f591e59cd0b14a28adaf9c0e327e0a"]


class BinaryHashClaim(_FrozenModel):
    path: str
    sha256: Sha256


class FirmwareClaims(_FrozenModel):
    version: Literal["2.57"]
    product: Literal["SNOWSKY_DISC"]
    main_os_version: Literal[257] = Field(alias="mainOsVersion")
    recovery_os_version: Literal[18] = Field(alias="recoveryOsVersion")
    rootfs_chunks: Literal[77] = Field(alias="rootfsChunks")
    rootfs_bytes: Literal[80596992] = Field(alias="rootfsBytes")
    rootfs_sha256: Literal["111e4dd7ee3d7ff91ba7e61181690be7ffd22bd1bbd13ad513f5f015ffb302ae"] = (
        Field(alias="rootfsSha256")
    )
    original_binaries: tuple[BinaryHashClaim, ...] = Field(alias="originalBinaries")

    @model_validator(mode="after")
    def require_the_six_pinned_binary_claims(self) -> FirmwareClaims:
        paths = tuple(binary.path for binary in self.original_binaries)
        if len(paths) != 6 or set(paths) != _BINARY_PATHS:
            raise ValueError("The V2.57 reference must contain its six pinned binary claims")
        return self


class ParserGrammar(_FrozenModel):
    matching_mode: Literal["fullmatch"] = Field(alias="matchingMode")
    chunk_filename_regex: Literal[r"rootfs\.squashfs\.(\d{4})\.([a-f0-9]{64})\.enc"] = Field(
        alias="chunkFilenameRegex"
    )
    manifest_entry_regex: Literal[
        r"SHA256\(ota/(rootfs\.squashfs\.\d{4}\.[a-f0-9]{64}\.enc)\)= ([a-f0-9]{64})"
    ] = Field(alias="manifestEntryRegex")
    ota_config_version_keys: tuple[Literal["current_version", "recovery_version"], ...] = Field(
        alias="otaConfigVersionKeys"
    )
    ota_config_version_value_regex: Literal[r"[1-9]\d{0,5}"] = Field(
        alias="otaConfigVersionValueRegex"
    )

    @model_validator(mode="after")
    def require_both_version_keys(self) -> ParserGrammar:
        if set(self.ota_config_version_keys) != {"current_version", "recovery_version"}:
            raise ValueError("The pinned parser grammar must name both OTA version fields")
        return self


class FirmwareIntakeReference(_FrozenModel):
    reference_version: Literal[1] = Field(alias="referenceVersion")
    claim_status: Literal["upstream-claim-only"] = Field(alias="claimStatus")
    authenticity_status: Literal["unverified"] = Field(alias="authenticityStatus")
    upstream: UpstreamRepository
    profile_source: ProfileSourceIdentity = Field(alias="profileSource")
    parser_source: ParserSourceIdentity = Field(alias="parserSource")
    firmware_claims: FirmwareClaims = Field(alias="firmwareClaims")
    parser_grammar: ParserGrammar = Field(alias="parserGrammar")

    @property
    def version(self) -> str:
        return self.firmware_claims.version

    @property
    def product(self) -> str:
        return self.firmware_claims.product

    @property
    def main_os_version(self) -> int:
        return self.firmware_claims.main_os_version

    @property
    def recovery_os_version(self) -> int:
        return self.firmware_claims.recovery_os_version

    @property
    def rootfs_chunks(self) -> int:
        return self.firmware_claims.rootfs_chunks

    @property
    def rootfs_size(self) -> int:
        """Return the upstream-declared reconstructed rootfs byte count."""
        return self.firmware_claims.rootfs_bytes

    @property
    def rootfs_sha256(self) -> str:
        return self.firmware_claims.rootfs_sha256

    @property
    def original_binaries(self) -> tuple[BinaryHashClaim, ...]:
        return self.firmware_claims.original_binaries


@dataclass(frozen=True, slots=True)
class LoadedFirmwareReference:
    """Validated reference metadata plus the SHA-256 of its packaged JSON bytes."""

    metadata: FirmwareIntakeReference
    sha256: Sha256


def load_reference() -> LoadedFirmwareReference:
    """Load the bundled V2.57 reference without accessing firmware or upstreams.

    The returned digest covers the exact JSON bytes packaged with this module.
    The firmware values remain upstream claims; this loader does not verify a
    user-supplied package, authenticate firmware, or enable runtime selection.
    """
    resource = files("snowsky_disc_lab").joinpath("data", "v257-intake-reference.json")
    raw = resource.read_bytes()
    if hashlib.sha256(raw).hexdigest() != REFERENCE_SHA256:
        raise ValueError("Bundled V2.57 firmware intake reference identity mismatch")
    try:
        metadata = FirmwareIntakeReference.model_validate_json(raw)
    except ValidationError:
        raise ValueError("Invalid bundled V2.57 firmware intake reference") from None
    return LoadedFirmwareReference(metadata=metadata, sha256=hashlib.sha256(raw).hexdigest())


__all__ = ["FirmwareIntakeReference", "LoadedFirmwareReference", "load_reference"]
