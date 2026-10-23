"""Synthetic, firmware-free regressions for ``disc-lab firmware inspect``."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import stat
import struct
import subprocess
import zipfile
import zlib
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from snowsky_disc_lab.cli import app
from snowsky_disc_lab.firmware_intake import IntakeReceipt

runner = CliRunner()
CHUNK_COUNT = 77
RECEIPT_VERSION = "lab-firmware-intake/v1"
CONDITION_STATUSES = {"verified", "unverified", "unsupported", "rejected"}


def _chunk_name(index: int) -> str:
    # The upstream-looking name is intentionally unrelated to the chunk bytes.
    opaque_name_hash = hashlib.sha256(f"synthetic-upstream-name-{index:04d}".encode()).hexdigest()
    return f"rootfs.squashfs.{index:04d}.{opaque_name_hash}.enc"


def _chunk_bytes(index: int) -> bytes:
    return f"synthetic opaque encrypted chunk {index:04d}\0".encode()


def _make_package(
    root: Path,
    *,
    main_version: int = 257,
    recovery_version: int = 18,
    chunk_indices: range | list[int] | None = None,
    extra_chunks: list[tuple[str, bytes]] | None = None,
    config: str | None = None,
    manifest: str | None = None,
    signature: bytes | None = None,
) -> tuple[Path, dict[str, bytes]]:
    root.mkdir(parents=True, exist_ok=True)
    if config is None:
        config = f"current_version={main_version}\nrecovery_version={recovery_version}\n"
    (root / "ota_config.in").write_text(config, encoding="utf-8", newline="\n")

    ota = root / "main_os" / f"ota_v{main_version}"
    ota.mkdir(parents=True)
    indices = list(range(CHUNK_COUNT)) if chunk_indices is None else list(chunk_indices)
    chunks: dict[str, bytes] = {}
    rows: list[str] = []
    for index in indices:
        name = _chunk_name(index)
        data = _chunk_bytes(index)
        (ota / name).write_bytes(data)
        chunks[name] = data
        rows.append(f"SHA256(ota/{name})= {hashlib.sha256(data).hexdigest()}")
    for name, data in extra_chunks or []:
        (ota / name).write_bytes(data)
        chunks[name] = data
    if manifest is None:
        manifest = "\n".join(rows) + "\n"
    (ota / "manifest.sha256").write_text(manifest, encoding="utf-8", newline="\n")
    if signature is not None:
        (ota / "manifest.sha256.sig").write_bytes(signature)
    return root, chunks


def _add_manifested_main_member(package: Path, name: str, data: bytes) -> None:
    ota = package / "main_os" / "ota_v257"
    (ota / name).write_bytes(data)
    manifest = ota / "manifest.sha256"
    with manifest.open("a", encoding="utf-8", newline="\n") as output:
        output.write(f"SHA256(ota/{name})= {hashlib.sha256(data).hexdigest()}\n")


def _zip_package(
    directory: Path,
    archive: Path,
    *,
    wrapper: str | None = None,
    extra_entries: list[tuple[str, bytes]] | None = None,
    symlink_entry: str | None = None,
    compression: int = zipfile.ZIP_STORED,
) -> Path:
    prefix = f"{wrapper.strip('/')}/" if wrapper else ""
    with zipfile.ZipFile(archive, "w", compression=compression) as output:
        for source in sorted(path for path in directory.rglob("*") if path.is_file()):
            relative = source.relative_to(directory).as_posix()
            output.write(source, prefix + relative)
        for name, data in extra_entries or []:
            output.writestr(prefix + name, data)
        if symlink_entry is not None:
            info = zipfile.ZipInfo(prefix + symlink_entry)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            output.writestr(info, b"synthetic-target")
    return archive


def _extra_field(field_id: int, payload: bytes) -> bytes:
    return struct.pack("<HH", field_id, len(payload)) + payload


def _zip_metadata(*, central: bool, mtime: int = 100, uid: int = 1000, gid: int = 1000) -> bytes:
    timestamp = struct.pack("<BI", 3, mtime)
    if not central:
        timestamp += struct.pack("<I", 200)  # Local atime; central stores only mtime.
    unix_ids = struct.pack("<BBIBI", 1, 4, uid, 4, gid)
    return _extra_field(0x5455, timestamp) + _extra_field(0x7875, unix_ids)


def _zip_with_header_metadata(
    package: Path,
    archive: Path,
    *,
    first_local: bytes | None = None,
    first_central: bytes | None = None,
    gap: bytes = b"",
) -> Path:
    """Write stored ZIP records independently of the intake parser and ZipFile writer.

    ZipFile's writer copies one extra blob into both headers. Constructing records
    here lets fixtures represent the distinct Info-ZIP central/local forms.
    Only the first record is mutated; sizes, CRCs and offsets stay consistent.
    """
    records = bytearray()
    directory = bytearray()
    sources = sorted(path for path in package.rglob("*") if path.is_file())
    for index, source in enumerate(sources):
        name = source.relative_to(package).as_posix().encode("ascii")
        content = source.read_bytes()
        local_extra = _zip_metadata(central=False)
        central_extra = _zip_metadata(central=True)
        if index == 0:
            if first_local is not None:
                local_extra = first_local
            if first_central is not None:
                central_extra = first_central
        crc = zlib.crc32(content)
        offset = len(records)
        records.extend(
            struct.pack(
                "<4s5H3I2H",
                b"PK\x03\x04",
                20,
                0,
                0,
                0,
                33,
                crc,
                len(content),
                len(content),
                len(name),
                len(local_extra),
            )
            + name
            + local_extra
            + content
        )
        directory.extend(
            struct.pack(
                "<4s6H3I5H2I",
                b"PK\x01\x02",
                20,
                20,
                0,
                0,
                0,
                33,
                crc,
                len(content),
                len(content),
                len(name),
                len(central_extra),
                0,
                0,
                0,
                0,
                offset,
            )
            + name
            + central_extra
        )
        if index == 0:
            records.extend(gap)
    end = struct.pack(
        "<4s4H2IH",
        b"PK\x05\x06",
        0,
        0,
        len(sources),
        len(sources),
        len(directory),
        len(records),
        0,
    )
    archive.write_bytes(records + directory + end)
    return archive


def _inspect(path: Path, output_format: str = "json"):
    return runner.invoke(app, ["firmware", "inspect", str(path), "--format", output_format])


def _receipt(result: Any, *, expected_status: str) -> dict[str, Any]:
    assert result.exit_code == (0 if expected_status == "accepted" else 2), result.output
    try:
        receipt = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError) as error:
        pytest.fail(
            f"inspect --format json must return a JSON receipt: {error}; output={result.output!r}"
        )

    assert receipt["api_version"] == RECEIPT_VERSION
    assert receipt["status"] == expected_status
    assert receipt["may_proceed"] is False
    assert receipt["extraction_authorized"] is False
    assert receipt["execution_authorized"] is False
    assert receipt["observed_product"] is None
    assert isinstance(receipt["conditions"], list)
    for condition in receipt["conditions"]:
        assert set(condition) >= {"check", "status", "code"}
        assert isinstance(condition["check"], str) and condition["check"]
        assert condition["status"] in CONDITION_STATUSES
        assert isinstance(condition["code"], str) and condition["code"]
    return receipt


def _assert_accepted(
    receipt: dict[str, Any], *, input_format: str, chunks: dict[str, bytes]
) -> None:
    assert receipt["input_format"] == input_format
    assert isinstance(receipt["package_sha256"], str)
    assert re.fullmatch(r"[0-9a-f]{64}", receipt["package_sha256"])
    assert receipt["chunk_count"] == CHUNK_COUNT
    assert len(receipt["chunks"]) == CHUNK_COUNT
    by_name = {chunk["filename_hash"]: chunk for chunk in receipt["chunks"]}
    expected_filename_hashes = {
        _chunk_name(index).removeprefix(f"rootfs.squashfs.{index:04d}.").removesuffix(".enc")
        for index in range(CHUNK_COUNT)
    }
    assert set(by_name) == expected_filename_hashes
    for index in range(CHUNK_COUNT):
        name = _chunk_name(index)
        filename_hash = name.removeprefix(f"rootfs.squashfs.{index:04d}.").removesuffix(".enc")
        data = chunks[name]
        chunk = by_name[filename_hash]
        assert chunk["index"] == index
        assert chunk["size"] == len(data)
        assert chunk["sha256"] == hashlib.sha256(data).hexdigest()
        assert chunk["manifest_sha256"] == hashlib.sha256(data).hexdigest()
        assert chunk["filename_hash"] == filename_hash
        # A hex filename is an opaque upstream identifier, not a claimed ciphertext digest.
        assert chunk["filename_hash"] != chunk["sha256"]


def _assert_refused(result: Any, *, input_format: str | None = None) -> dict[str, Any]:
    receipt = _receipt(result, expected_status="refused")
    if input_format is not None:
        assert receipt["input_format"] == input_format
    return receipt


def _assert_refused_code(
    result: Any, code: str, *, input_format: str | None = None
) -> dict[str, Any]:
    receipt = _assert_refused(result, input_format=input_format)
    rejected_codes = [
        condition["code"]
        for condition in receipt["conditions"]
        if condition["status"] == "rejected"
    ]
    assert code in rejected_codes, f"expected refusal code {code!r}, got {rejected_codes!r}"
    return receipt


def _snapshot(candidate: Path) -> tuple[tuple[str, str, int | str], ...]:
    if candidate.is_file():
        data = candidate.read_bytes()
        return ((candidate.name, hashlib.sha256(data).hexdigest(), len(data)),)

    entries: list[tuple[str, str, int | str]] = []
    for path in [candidate, *sorted(candidate.rglob("*"))]:
        relative = "." if path == candidate else path.relative_to(candidate).as_posix()
        if path.is_symlink():
            entries.append((relative, "symlink", os.readlink(path)))
        elif path.is_dir():
            entries.append((relative, "directory", ""))
        elif path.is_file():
            data = path.read_bytes()
            entries.append((relative, hashlib.sha256(data).hexdigest(), len(data)))
    return tuple(entries)


def _patch_zip_flags(
    archive: Path,
    *,
    set_local: int = 0,
    set_central: int = 0,
    clear_local: int = 0,
    clear_central: int = 0,
) -> None:
    data = bytearray(archive.read_bytes())
    local_signature = b"PK\x03\x04"
    central_signature = b"PK\x01\x02"
    offset = 0
    while True:
        offset = data.find(local_signature, offset)
        if offset < 0:
            break
        flags = struct.unpack_from("<H", data, offset + 6)[0]
        flags = (flags | set_local) & ~clear_local
        struct.pack_into("<H", data, offset + 6, flags)
        offset += len(local_signature)
    offset = 0
    while True:
        offset = data.find(central_signature, offset)
        if offset < 0:
            break
        flags = struct.unpack_from("<H", data, offset + 8)[0]
        flags = (flags | set_central) & ~clear_central
        struct.pack_into("<H", data, offset + 8, flags)
        offset += len(central_signature)
    archive.write_bytes(data)


def _patch_eocd_counts(archive: Path, *, disk_delta: int = 0, total_delta: int = 0) -> None:
    data = bytearray(archive.read_bytes())
    end_signature = b"PK\x05\x06"
    offset = data.rfind(end_signature)
    assert offset >= 0
    disk_entries, total_entries = struct.unpack_from("<HH", data, offset + 8)
    struct.pack_into("<H", data, offset + 8, disk_entries + disk_delta)
    struct.pack_into("<H", data, offset + 10, total_entries + total_delta)
    archive.write_bytes(data)


def test_firmware_inspect_accepts_synthetic_directory_as_data_only(tmp_path: Path) -> None:
    package, chunks = _make_package(
        tmp_path / "synthetic-package", signature=b"opaque synthetic signature bytes"
    )

    result = _inspect(package)

    receipt = _receipt(result, expected_status="accepted")
    _assert_accepted(receipt, input_format="directory", chunks=chunks)
    assert receipt["archive_sha256"] is None
    assert receipt["observed_main"] == 257
    assert receipt["observed_recovery"] == 18
    signature_condition = next(
        condition
        for condition in receipt["conditions"]
        if condition["check"] == "signature_verification"
    )
    assert signature_condition["status"] == "unsupported"
    assert "opaque synthetic signature bytes" not in result.output


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_chunk",
        "reordered_chunks",
        "incomplete_scan",
        "contradictory_condition",
        "authenticity_status",
        "authenticity_code",
        "unexpected_condition",
    ],
)
def test_accepted_intake_receipt_rejects_inconsistent_semantic_evidence(
    tmp_path: Path, mutation: str
) -> None:
    package, _chunks = _make_package(tmp_path / "synthetic-package")
    raw = _receipt(_inspect(package), expected_status="accepted")
    if mutation == "missing_chunk":
        raw["chunks"].pop()
    elif mutation == "reordered_chunks":
        raw["chunks"][0], raw["chunks"][1] = raw["chunks"][1], raw["chunks"][0]
    elif mutation == "incomplete_scan":
        raw["inspection_complete"] = False
    elif mutation == "contradictory_condition":
        condition = next(
            item for item in raw["conditions"] if item["check"] == "structure_and_integrity"
        )
        condition["status"] = "unverified"
    elif mutation in {"authenticity_status", "authenticity_code"}:
        condition = next(
            item for item in raw["conditions"] if item["check"] == "vendor_authenticity"
        )
        field = "status" if mutation == "authenticity_status" else "code"
        condition[field] = "verified" if field == "status" else "invented_trust_code"
    else:
        raw["conditions"].append(
            {"check": "invented_gate", "status": "verified", "code": "owner_claim"}
        )

    with pytest.raises(ValidationError):
        IntakeReceipt.model_validate(raw)


def test_refused_intake_receipt_remains_parseable_without_authority(tmp_path: Path) -> None:
    package, _chunks = _make_package(tmp_path / "synthetic-package", main_version=258)

    receipt = IntakeReceipt.model_validate(_receipt(_inspect(package), expected_status="refused"))

    assert receipt.status == "refused"
    assert receipt.may_proceed is False
    assert receipt.extraction_authorized is False


@pytest.mark.parametrize("wrapper", [None, "single-wrapper"])
def test_firmware_inspect_accepts_zip_root_or_one_wrapper(
    tmp_path: Path, wrapper: str | None
) -> None:
    package, chunks = _make_package(tmp_path / "synthetic-package")
    archive = _zip_package(package, tmp_path / "synthetic-package.zip", wrapper=wrapper)

    result = _inspect(archive)

    receipt = _receipt(result, expected_status="accepted")
    _assert_accepted(receipt, input_format="zip", chunks=chunks)
    assert re.fullmatch(r"[0-9a-f]{64}", receipt["archive_sha256"])
    assert receipt["observed_main"] == 257
    assert receipt["observed_recovery"] == 18
    assert not (tmp_path / "main_os").exists(), "ZIP inspection must not extract the archive"


def test_firmware_inspect_default_format_is_human_readable(tmp_path: Path) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package")

    result = runner.invoke(app, ["firmware", "inspect", str(package)])

    assert result.exit_code == 0, result.output
    assert "accepted" in result.stdout.lower()
    assert "execution_authorized" not in result.stdout


@pytest.mark.parametrize(
    ("config", "refusal_code"),
    [
        (
            "current_version=257\ncurrent_version=258\nrecovery_version=18\n",
            "duplicate_metadata",
        ),
        (
            "current_version=two-fifty-seven\nrecovery_version=18\n",
            "unsupported_or_malformed_config",
        ),
        (
            "current_version=257\nrecovery_version=18\nunknown_key=secret-config-token\n",
            "unsupported_or_malformed_config",
        ),
    ],
    ids=["duplicate-key", "malformed-value", "unknown-field"],
)
def test_firmware_inspect_refuses_malformed_or_duplicate_config(
    tmp_path: Path, config: str, refusal_code: str
) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package", config=config)

    result = _inspect(package)

    receipt = _assert_refused_code(result, refusal_code, input_format="directory")
    assert receipt["observed_main"] is None
    assert "secret-config-token" not in result.output


@pytest.mark.parametrize(
    ("manifest", "refusal_code"),
    [
        ("not a sha256 manifest row\n", "malformed_manifest"),
        # Repeating an otherwise valid record is ambiguous and must not be collapsed.
        (None, "duplicate_manifest_entry"),
    ],
    ids=["malformed-record", "duplicate-record"],
)
def test_firmware_inspect_refuses_malformed_manifest_rows(
    tmp_path: Path, manifest: str | None, refusal_code: str
) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package", manifest=manifest)
    if manifest is None:
        manifest_path = package / "main_os" / "ota_v257" / "manifest.sha256"
        rows = manifest_path.read_text(encoding="utf-8").splitlines()
        manifest_path.write_text("\n".join([rows[0], rows[0], *rows[1:]]) + "\n", encoding="utf-8")

    _assert_refused_code(_inspect(package), refusal_code, input_format="directory")


def test_firmware_inspect_refuses_duplicate_manifest_archive_entry(tmp_path: Path) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package")
    manifest = (package / "main_os" / "ota_v257" / "manifest.sha256").read_bytes()
    archive = _zip_package(
        package,
        tmp_path / "duplicate-manifest.zip",
        extra_entries=[("main_os/ota_v257/manifest.sha256", manifest)],
    )

    _assert_refused_code(_inspect(archive), "duplicate_or_case_collision", input_format="zip")


@pytest.mark.parametrize(
    ("chunk_indices", "extra_chunks", "refusal_code"),
    [
        (list(range(CHUNK_COUNT - 1)), None, "rootfs_chunk_structure_mismatch"),
        (
            None,
            [("unexpected-extra.enc", b"synthetic extra chunk")],
            "unsupported_ota_member",
        ),
    ],
    ids=["missing-chunk", "extra-chunk"],
)
def test_firmware_inspect_refuses_missing_or_extra_chunks(
    tmp_path: Path,
    chunk_indices: list[int] | None,
    extra_chunks: list[tuple[str, bytes]] | None,
    refusal_code: str,
) -> None:
    package, _ = _make_package(
        tmp_path / "synthetic-package", chunk_indices=chunk_indices, extra_chunks=extra_chunks
    )

    _assert_refused_code(_inspect(package), refusal_code, input_format="directory")


def test_firmware_inspect_refuses_valid_manifest_extra_rootfs_index(tmp_path: Path) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package")
    _add_manifested_main_member(package, _chunk_name(CHUNK_COUNT), _chunk_bytes(CHUNK_COUNT))

    _assert_refused_code(
        _inspect(package), "rootfs_chunk_structure_mismatch", input_format="directory"
    )


def test_firmware_inspect_refuses_nonrootfs_manifest_record(tmp_path: Path) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package")
    _add_manifested_main_member(package, "ancillary-player.enc", b"synthetic ancillary bytes")

    _assert_refused_code(_inspect(package), "malformed_manifest", input_format="directory")


def test_firmware_inspect_refuses_a_bare_ota_directory(tmp_path: Path) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package")
    bare_ota = package / "main_os" / "ota_v257"

    result = _inspect(bare_ota)

    _assert_refused_code(result, "missing_or_ambiguous_package_config", input_format="directory")


def test_firmware_inspect_refuses_manifest_checksum_mismatch(tmp_path: Path) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package")
    target = package / "main_os" / "ota_v257" / f"{_chunk_name(0)}"
    target.write_bytes(b"different synthetic opaque bytes")

    _assert_refused_code(_inspect(package), "chunk_checksum_mismatch", input_format="directory")


def test_firmware_inspect_refuses_unknown_version(tmp_path: Path) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package", main_version=999)

    receipt = _assert_refused_code(
        _inspect(package), "unknown_firmware_reference", input_format="directory"
    )
    assert receipt["observed_main"] == 999


def test_firmware_inspect_refuses_recovery_version_mismatch(tmp_path: Path) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package", recovery_version=19)

    receipt = _assert_refused_code(
        _inspect(package), "unknown_firmware_reference", input_format="directory"
    )

    assert receipt["observed_main"] == 257
    assert receipt["observed_recovery"] == 19


@pytest.mark.parametrize(
    "entry_name",
    [
        "../outside-secret-token.txt",
        "C:/absolute-secret-token.txt",
        r"..\outside-secret-token.txt",
        r"C:\absolute-secret-token.txt",
    ],
    ids=["parent-traversal", "drive-absolute", "backslash-traversal", "backslash-drive-absolute"],
)
def test_firmware_inspect_refuses_unsafe_zip_paths(tmp_path: Path, entry_name: str) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package")
    archive = _zip_package(
        package,
        tmp_path / "unsafe-path.zip",
        extra_entries=[(entry_name, b"synthetic marker")],
    )

    result = _inspect(archive)

    _assert_refused_code(result, "unsafe_member_path", input_format="zip")
    assert "outside-secret-token" not in result.output
    assert "absolute-secret-token" not in result.output


def test_firmware_inspect_refuses_case_colliding_zip_paths(tmp_path: Path) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package")
    manifest = (package / "main_os" / "ota_v257" / "manifest.sha256").read_bytes()
    archive = _zip_package(
        package,
        tmp_path / "case-collision.zip",
        extra_entries=[("MAIN_OS/OTA_V257/manifest.sha256", manifest)],
    )

    _assert_refused_code(_inspect(archive), "duplicate_or_case_collision", input_format="zip")


def test_firmware_inspect_refuses_case_colliding_directory_paths(tmp_path: Path) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package")
    first = package / "SyntheticCaseMarker.txt"
    second = package / "syntheticcasemarker.txt"
    first.write_text("synthetic first spelling", encoding="utf-8")
    try:
        second.write_text("synthetic second spelling", encoding="utf-8")
    except OSError as error:
        pytest.skip(f"case-sensitive sibling names are unavailable: {error}")
    names = {path.name for path in package.iterdir()}
    if {first.name, second.name} - names:
        pytest.skip("filesystem does not preserve case-colliding sibling names")

    _assert_refused_code(_inspect(package), "duplicate_or_case_collision", input_format="directory")


def test_firmware_inspect_refuses_hard_linked_files(tmp_path: Path) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package")
    target = package / "main_os" / "ota_v257" / _chunk_name(0)
    linked = tmp_path / "synthetic-hardlink.enc"
    try:
        os.link(target, linked)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"hard links are unavailable: {error}")

    _assert_refused_code(_inspect(package), "hard_link_unsupported", input_format="directory")


def test_firmware_inspect_refuses_fifo_without_opening_or_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name == "nt":
        pytest.skip("POSIX FIFO required")
    mkfifo = getattr(os, "mkfifo", None)
    if mkfifo is None:
        pytest.skip("POSIX FIFO creation is unavailable")
    assert mkfifo is not None
    from snowsky_disc_lab import firmware_intake

    package, _ = _make_package(tmp_path / "synthetic-package")
    fifo = package / "synthetic-fifo-marker"
    mkfifo(fifo)
    real_open = os.open

    def guarded_open(path: str | bytes | os.PathLike[str] | os.PathLike[bytes], *args: Any) -> int:
        if os.path.abspath(os.fspath(path)) == os.path.abspath(os.fspath(fifo)):
            pytest.fail("inspection attempted to open a FIFO and could block")
        return real_open(path, *args)

    monkeypatch.setattr(firmware_intake.os, "open", guarded_open)

    _assert_refused_code(_inspect(package), "not_regular_file", input_format="directory")


def test_firmware_inspect_detects_input_modified_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from snowsky_disc_lab import firmware_intake

    package, _ = _make_package(tmp_path / "synthetic-package")
    target = package / "main_os" / "ota_v257" / _chunk_name(0)
    original_consume = firmware_intake._Inspection.consume
    changed = False

    def consume_then_touch(inspection: Any, name: str, stream: Any, expected_size: int) -> None:
        nonlocal changed
        original_consume(inspection, name, stream, expected_size)
        if not changed and name.endswith(_chunk_name(0)):
            before = target.stat()
            os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns + 5_000_000_000))
            changed = True

    monkeypatch.setattr(firmware_intake._Inspection, "consume", consume_then_touch)

    result = _inspect(package)

    assert changed
    _assert_refused_code(result, "input_changed", input_format="directory")


def test_firmware_inspect_refuses_zip_symlinks(tmp_path: Path) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package")
    archive = _zip_package(
        package,
        tmp_path / "symlink.zip",
        symlink_entry="main_os/ota_v257/synthetic-link.enc",
    )

    _assert_refused_code(_inspect(archive), "unsafe_zip_file_type", input_format="zip")


def test_firmware_inspect_refuses_directory_symlink_when_supported(tmp_path: Path) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package")
    ota = package / "main_os" / "ota_v257"
    linked_chunk = ota / _chunk_name(0)
    linked_chunk.unlink()
    outside = tmp_path / "outside-synthetic-secret-token.enc"
    outside.write_bytes(b"synthetic external bytes")
    try:
        linked_chunk.symlink_to(outside)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"directory symlinks are unavailable: {error}")

    result = _inspect(package)

    _assert_refused_code(result, "unsafe_link_or_reparse_point", input_format="directory")
    assert outside.read_bytes() == b"synthetic external bytes"
    assert str(outside) not in result.output


def test_firmware_inspect_refuses_nested_archives(tmp_path: Path) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package")
    archive = _zip_package(
        package,
        tmp_path / "nested-archive.zip",
        extra_entries=[("main_os/ota_v257/nested.zip", b"PK\x03\x04 synthetic nested archive")],
    )

    _assert_refused_code(_inspect(archive), "nested_archive_unsupported", input_format="zip")


@pytest.mark.parametrize("mode", ["encrypted", "local-header-mismatch"])
def test_firmware_inspect_refuses_zip_encryption_flags_or_header_mismatch(
    tmp_path: Path, mode: str
) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package")
    archive = _zip_package(package, tmp_path / "flags.zip")
    if mode == "encrypted":
        _patch_zip_flags(archive, set_local=1, set_central=1)
        refusal_code = "encrypted_zip_unsupported"
    else:
        _patch_zip_flags(archive, set_local=1)
        refusal_code = "inconsistent_local_header"

    _assert_refused_code(_inspect(archive), refusal_code, input_format="zip")


def test_firmware_inspect_refuses_inconsistent_eocd_entry_counts(tmp_path: Path) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package")
    archive = _zip_package(package, tmp_path / "bad-eocd-count.zip")
    _patch_eocd_counts(archive, total_delta=1)

    _assert_refused_code(_inspect(archive), "multipart_zip_unsupported", input_format="zip")


@pytest.mark.parametrize(
    ("mutation", "refusal_code"),
    [
        ("none", None),
        ("mtime", "zip_timestamp_conflict"),
        ("uid", "zip_unix_ids_conflict"),
        ("gid", "zip_unix_ids_conflict"),
        ("truncated-local-payload", "zip_extra_field_malformed"),
        ("truncated-local-header", "zip_extra_field_malformed"),
        ("malformed-local-timestamp", "zip_timestamp_malformed"),
        ("duplicate-local-timestamp", "zip_extra_field_duplicate"),
        ("duplicate-local-unix", "zip_extra_field_duplicate"),
        ("unknown-local-id", "zip_extra_field_unsupported"),
        ("duplicate-central-timestamp", "zip_extra_field_duplicate"),
        ("unknown-central-id", "zip_extra_field_unsupported"),
        ("hidden-padding", "unindexed_zip_bytes"),
    ],
)
def test_firmware_inspect_zip_header_metadata_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str, refusal_code: str | None
) -> None:
    package, chunks = _make_package(tmp_path / "synthetic-package")
    local = _zip_metadata(central=False)
    central = _zip_metadata(central=True)
    if mutation == "mtime":
        local = _zip_metadata(central=False, mtime=101)
    elif mutation == "uid":
        local = _zip_metadata(central=False, uid=1001)
    elif mutation == "gid":
        local = _zip_metadata(central=False, gid=1001)
    elif mutation == "truncated-local-payload":
        local = local[:-1]  # Keep TLV length but omit its final byte.
    elif mutation == "truncated-local-header":
        local += b"\x55\x54\x05"  # Incomplete four-byte TLV header.
    elif mutation == "malformed-local-timestamp":
        local = _extra_field(0x5455, struct.pack("<BI", 3, 100))
    elif mutation == "duplicate-local-timestamp":
        local += _extra_field(0x5455, struct.pack("<BII", 3, 100, 200))
    elif mutation == "duplicate-local-unix":
        local += _extra_field(0x7875, struct.pack("<BBIBI", 1, 4, 1000, 4, 1000))
    elif mutation == "unknown-local-id":
        local += _extra_field(0x9999, b"")
    elif mutation == "duplicate-central-timestamp":
        central += _extra_field(0x5455, struct.pack("<BI", 3, 100))
    elif mutation == "unknown-central-id":
        central += _extra_field(0x9999, b"")
    archive = _zip_with_header_metadata(
        package,
        tmp_path / "synthetic-extra-fields.zip",
        first_local=local,
        first_central=central,
        gap=b"hidden padding" if mutation == "hidden-padding" else b"",
    )
    if mutation == "none":
        # Check the fixture's byte geometry independently, including nonzero extras.
        raw = archive.read_bytes()
        offset = 0
        with zipfile.ZipFile(archive) as indexed:
            assert len(indexed.infolist()) == 79
            for member in indexed.infolist():
                assert member.header_offset == offset
                name_bytes, extra_bytes = struct.unpack_from("<HH", raw, offset + 26)
                assert extra_bytes == 28
                extra_start = offset + 30 + name_bytes
                assert raw[extra_start : extra_start + extra_bytes] == local
                assert member.extra == central
                offset = extra_start + extra_bytes + member.compress_size
        assert offset == struct.unpack_from("<I", raw, len(raw) - 6)[0]

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("intake must not extract, execute processes, or contact the network")

    monkeypatch.setattr(zipfile.ZipFile, "extract", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    before = _snapshot(tmp_path)
    result = _inspect(archive)
    if refusal_code is None:
        receipt = _receipt(result, expected_status="accepted")
        _assert_accepted(receipt, input_format="zip", chunks=chunks)
        assert receipt["inspection_complete"] is True
        assert (receipt["observed_main"], receipt["observed_recovery"]) == (257, 18)
        assert receipt["archive_sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    else:
        receipt = _assert_refused_code(result, refusal_code, input_format="zip")
        assert receipt["inspection_complete"] is False
        assert [c["code"] for c in receipt["conditions"] if c["status"] == "rejected"] == [
            refusal_code
        ]
    assert receipt["vendor_authenticity"] == "unverified"
    assert receipt["compatibility"] == "unverified"
    assert _snapshot(tmp_path) == before


def test_zip_extra_field_parsers_accept_bounded_timestamp_and_unix_ids() -> None:
    from snowsky_disc_lab.firmware_intake import (
        _parse_extra_fields,
        _timestamp_values,
        _unix_ids,
    )

    central = struct.pack("<B I", 1, 1_700_000_000)
    local = struct.pack("<B I I", 3, 1_700_000_000, 1_700_000_001)
    uid_gid = bytes([1, 2, 0x34, 0x12, 2, 0x78, 0x56])
    timestamp_field = struct.pack("<HH", 0x5455, len(central)) + central
    ids_field = struct.pack("<HH", 0x7875, len(uid_gid)) + uid_gid
    assert _timestamp_values(_parse_extra_fields(timestamp_field)[0x5455], central=True) == {
        "mtime": 1_700_000_000
    }
    assert _timestamp_values(local) == {"mtime": 1_700_000_000, "atime": 1_700_000_001}
    assert _unix_ids(_parse_extra_fields(ids_field)[0x7875]) == (0x1234, 0x5678)


def test_zip_extra_fields_allow_header_timestamp_layout_difference_and_match_mtime() -> None:
    from snowsky_disc_lab.firmware_intake import _validate_extra_pair

    central_payload = struct.pack("<B I", 3, 1_700_000_000)
    local_payload = struct.pack("<B I I", 3, 1_700_000_000, 1_700_000_001)
    central = struct.pack("<HH", 0x5455, len(central_payload)) + central_payload
    local = struct.pack("<HH", 0x5455, len(local_payload)) + local_payload
    _validate_extra_pair(central, local)

    conflicting = struct.pack("<B I I", 3, 1_700_000_002, 1_700_000_001)
    with pytest.raises(ValueError, match="zip_timestamp_conflict"):
        _validate_extra_pair(
            central,
            struct.pack("<HH", 0x5455, len(conflicting)) + conflicting,
        )


@pytest.mark.parametrize(
    "payload",
    [b"\x02\x01\x01\x01\x01", b"\x01\x00\x01\x01", b"\x01\x05\x01\x02\x01\x01"],
    ids=["unknown-version", "zero-width", "width-over-four"],
)
def test_zip_unix_ids_reject_unknown_version_and_invalid_widths(payload: bytes) -> None:
    from snowsky_disc_lab.firmware_intake import Refusal, _unix_ids

    with pytest.raises(Refusal, match="zip_unix_ids_malformed"):
        _unix_ids(payload)


def test_zip_extra_fields_reject_duplicates_and_unknown_ids() -> None:
    from snowsky_disc_lab.firmware_intake import Refusal, _parse_extra_fields

    timestamp = struct.pack("<HHB I", 0x5455, 5, 1, 1)
    with pytest.raises(Refusal, match="zip_extra_field_duplicate"):
        _parse_extra_fields(timestamp + timestamp)
    with pytest.raises(Refusal, match="zip_extra_field_unsupported"):
        _parse_extra_fields(struct.pack("<HH", 0x9999, 0))


@pytest.mark.parametrize(
    ("field", "code"),
    [
        (b"\x55\x54\x01", "zip_extra_field_malformed"),
        (struct.pack("<HH", 0x1234, 0), "zip_extra_field_unsupported"),
        (struct.pack("<HH", 0x5455, 5) + b"\x09xxxx", "zip_timestamp_malformed"),
        (struct.pack("<HH", 0x7875, 3) + b"\x02\x01\x00", "zip_unix_ids_malformed"),
    ],
)
def test_zip_extra_field_parsers_reject_malformed_or_unknown_fields(
    field: bytes, code: str
) -> None:
    from snowsky_disc_lab.firmware_intake import Refusal, _parse_extra_fields

    with pytest.raises(Refusal, match=code):
        parsed = _parse_extra_fields(field)
        if 0x5455 in parsed:
            from snowsky_disc_lab.firmware_intake import _timestamp_values

            _timestamp_values(parsed[0x5455])
        if 0x7875 in parsed:
            from snowsky_disc_lab.firmware_intake import _unix_ids

            _unix_ids(parsed[0x7875])


def test_firmware_inspect_crosschecks_eocd_count_against_central_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from snowsky_disc_lab import firmware_intake

    package, _ = _make_package(tmp_path / "synthetic-package")
    archive = _zip_package(package, tmp_path / "count-crosscheck.zip")
    real_preflight = firmware_intake._zip_preflight

    def mismatched_count(stream: Any, size: int) -> tuple[int, int]:
        count, offset = real_preflight(stream, size)
        return count + 1, offset

    monkeypatch.setattr(firmware_intake, "_zip_preflight", mismatched_count)

    _assert_refused_code(_inspect(archive), "zip_entry_count_mismatch", input_format="zip")


@pytest.mark.parametrize(
    ("constant", "value", "archive", "refusal_code"),
    [
        ("MAX_CHUNK_BYTES", 8, False, "member_size_limit"),
        ("MAX_TOTAL_BYTES", 128, False, "total_size_limit"),
        ("MAX_ENTRIES", 10, True, "entry_count_limit"),
    ],
    ids=["member-byte-limit", "total-byte-limit", "entry-count-limit"],
)
def test_firmware_inspect_enforces_resource_bounds_without_large_payloads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    value: int,
    archive: bool,
    refusal_code: str,
) -> None:
    from snowsky_disc_lab import firmware_intake

    package, _ = _make_package(tmp_path / "synthetic-package")
    candidate = _zip_package(package, tmp_path / "bounded.zip") if archive else package
    monkeypatch.setattr(firmware_intake, constant, value)

    result = _inspect(candidate)

    _assert_refused_code(result, refusal_code, input_format="zip" if archive else "directory")


@pytest.mark.parametrize(
    ("constant", "value", "refusal_code"),
    [
        ("MAX_CHUNK_BYTES", 8, "member_size_limit"),
        ("MAX_METADATA_BYTES", 8, "member_size_limit"),
        ("MAX_TOTAL_BYTES", 128, "total_size_limit"),
        ("MAX_DIRECTORY_BYTES", 1, "zip_directory_size_limit"),
    ],
    ids=["chunk-size", "metadata-size", "total-size", "central-directory-size"],
)
def test_firmware_inspect_enforces_zip_resource_bounds_without_large_payloads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    value: int,
    refusal_code: str,
) -> None:
    from snowsky_disc_lab import firmware_intake

    package, _ = _make_package(tmp_path / "synthetic-package")
    archive = _zip_package(package, tmp_path / "bounded.zip")
    monkeypatch.setattr(firmware_intake, constant, value)

    _assert_refused_code(_inspect(archive), refusal_code, input_format="zip")


def test_firmware_inspect_enforces_zip_compression_ratio_bound(tmp_path: Path) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package")
    archive = _zip_package(
        package,
        tmp_path / "high-ratio.zip",
        extra_entries=[("recovery/ota_v18/repetitive.enc", b"A" * 8192)],
        compression=zipfile.ZIP_DEFLATED,
    )

    _assert_refused_code(_inspect(archive), "compression_ratio_limit", input_format="zip")


def test_firmware_inspect_refuses_zip_member_with_bad_deflate_crc(tmp_path: Path) -> None:
    package, _ = _make_package(tmp_path / "synthetic-package")
    archive = _zip_package(package, tmp_path / "bad-crc.zip", compression=zipfile.ZIP_DEFLATED)
    member_name = f"main_os/ota_v257/{_chunk_name(0)}"
    with zipfile.ZipFile(archive) as source:
        info = source.getinfo(member_name)
        assert info.compress_type == zipfile.ZIP_DEFLATED
        assert not info.flag_bits & 8
    payload = bytearray(archive.read_bytes())
    wrong_crc = info.CRC ^ 1
    struct.pack_into("<I", payload, info.header_offset + 14, wrong_crc)
    central_signature = b"PK\x01\x02"
    offset = 0
    matched = False
    while True:
        offset = payload.find(central_signature, offset)
        if offset < 0:
            break
        name_size, extra_size, comment_size = struct.unpack_from("<HHH", payload, offset + 28)
        name_start = offset + 46
        name = bytes(payload[name_start : name_start + name_size]).decode("utf-8")
        if name == member_name:
            struct.pack_into("<I", payload, offset + 16, wrong_crc)
            matched = True
            break
        offset = name_start + name_size + extra_size + comment_size
    assert matched
    archive.write_bytes(payload)

    _assert_refused_code(_inspect(archive), "unreadable_or_invalid_input", input_format="zip")


@pytest.mark.parametrize(
    ("archive", "refuse"),
    [(False, False), (True, False), (False, True), (True, True)],
    ids=["directory-accepted", "zip-accepted", "directory-refused", "zip-refused"],
)
def test_firmware_inspect_keeps_inputs_unchanged_and_uses_no_external_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    archive: bool,
    refuse: bool,
) -> None:
    if refuse and not archive:
        package, _ = _make_package(
            tmp_path / "synthetic-package",
            config="current_version=257\ncurrent_version=257\nrecovery_version=18\n",
        )
    else:
        package, _ = _make_package(tmp_path / "synthetic-package")
    if archive:
        archive_extras = [("../outside-marker", b"synthetic refusal marker")] if refuse else None
        candidate = _zip_package(
            package, tmp_path / "synthetic-package.zip", extra_entries=archive_extras
        )
    else:
        candidate = package

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("firmware inspection must not start processes or contact the network")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    before = {path: _snapshot(path) for path in {package, candidate}}
    before_children = {path.name for path in tmp_path.iterdir()}

    result = _inspect(candidate)

    if refuse:
        reason = "duplicate_metadata" if not archive else "unsafe_member_path"
        _assert_refused_code(result, reason, input_format="zip" if archive else "directory")
    else:
        _receipt(result, expected_status="accepted")
    assert {path: _snapshot(path) for path in {package, candidate}} == before
    assert {path.name for path in tmp_path.iterdir()} == before_children


def test_firmware_inspect_refuses_missing_input_without_echoing_path_or_secret(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "secret-path-marker" / "missing-package.zip"

    result = _inspect(missing)

    receipt = _assert_refused_code(result, "unreadable_or_invalid_input", input_format="unknown")
    assert receipt["chunk_count"] == 0
    assert receipt["chunks"] == []
    assert str(missing) not in result.output
    assert "secret-path-marker" not in result.output
