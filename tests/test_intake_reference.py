"""Packaged first-party metadata must retain reviewed source identities and report semantics."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from snowsky_disc_lab.firmware_intake import IntakeReceipt
from snowsky_disc_lab.firmware_reference import REFERENCE_SHA256, load_reference

ROOT = Path(__file__).resolve().parents[1]


def test_reference_matches_preparation_and_is_not_an_executable_source_projection() -> None:
    reference = load_reference()
    preparation = json.loads((ROOT / "docs/m1-01-runtime-preparation.json").read_text())
    evidence = {row["path"]: row for row in preparation["evidenceFiles"]}
    for identity in [reference.metadata.profile_source, reference.metadata.parser_source]:
        assert identity.git_blob == evidence[identity.path]["gitBlob"]
        assert identity.sha256 == evidence[identity.path]["sha256"]
    active_version = evidence["firmware/active-version"]
    assert active_version["origin"] == "separate-public-source-review"
    assert active_version["gitBlob"] == "7521537d96663385b29fcf2863ca2d8b2a4d601c"
    assert active_version["sha256"] == (
        "614c56cf1dbf19349b8e7fd1fc7efdd918e1aa382b8faf6a55b83e220157bdfb"
    )
    assert reference.metadata.upstream.commit == preparation["integrationSource"]["commit"]
    claims = reference.metadata.firmware_claims
    previous = preparation["firmwareReference"]
    assert claims.rootfs_sha256 == previous["rootfsSha256"]
    assert claims.rootfs_bytes == previous["rootfsBytes"]
    assert {b.path: b.sha256 for b in claims.original_binaries} == previous["originalBinaries"]
    raw = (ROOT / "src/snowsky_disc_lab/data/v257-intake-reference.json").read_bytes()
    assert reference.sha256 == hashlib.sha256(raw).hexdigest() == REFERENCE_SHA256


def test_receipt_schema_and_fixed_no_authorization_fields() -> None:
    published = json.loads((ROOT / "schemas/lab-firmware-intake-v1.schema.json").read_text())
    assert IntakeReceipt.model_json_schema() == published
    for field in ["may_proceed", "extraction_authorized", "execution_authorized"]:
        with pytest.raises(ValidationError):
            IntakeReceipt.model_validate({field: True})


def test_changed_reference_bytes_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    class ChangedResource:
        def joinpath(self, *parts: str) -> ChangedResource:
            return self

        def read_bytes(self) -> bytes:
            return b'{"product":"forged"}'

    monkeypatch.setattr("snowsky_disc_lab.firmware_reference.files", lambda _: ChangedResource())
    with pytest.raises(ValueError, match="identity mismatch"):
        load_reference()
