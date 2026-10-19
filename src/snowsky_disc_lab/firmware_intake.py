"""Bounded offline intake; archive members are streamed, never extracted to disk."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
import time
import zipfile
import zlib
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Literal

from pydantic import BaseModel, ConfigDict, Field

# M1-02/V2.57 policy, not universal vendor limits. No user-controlled overrides.
MAX_ARCHIVE_BYTES = 1024**3
MAX_TOTAL_BYTES = 2 * 1024**3
MAX_ENTRIES = 4096
MAX_MEMBER_BYTES = 256 * 1024**2
MAX_CHUNK_BYTES = 4 * 1024**2
MAX_METADATA_BYTES = 64 * 1024
MAX_COMPRESSION_RATIO = 100
MAX_DIRECTORY_BYTES = 4 * 1024**2
MAX_DEPTH = 12
MAX_PATH_BYTES = 512
MAX_SECONDS = 60
BLOCK_BYTES = 64 * 1024

CHUNK = re.compile(r"rootfs\.squashfs\.(\d{4})\.([a-f0-9]{64})\.enc")
MANIFEST = re.compile(r"SHA256\(ota/(rootfs\.squashfs\.\d{4}\.[a-f0-9]{64}\.enc)\)= ([a-f0-9]{64})")
SAFE_COMPONENT = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*")
RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{i}" for i in range(10)),
    *(f"lpt{i}" for i in range(10)),
}
ARCHIVE_SUFFIXES = {".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".tgz"}


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Condition(_Model):
    check: str
    status: Literal["verified", "unverified", "unsupported", "rejected"]
    code: str


class ChunkIdentity(_Model):
    index: int
    size: int
    sha256: str
    manifest_sha256: str
    filename_hash: str


class IntakeReceipt(_Model):
    api_version: Literal["lab-firmware-intake/v1"] = "lab-firmware-intake/v1"
    policy: Literal["m1-02-v257"] = "m1-02-v257"
    status: Literal["accepted", "refused"] = "refused"
    input_format: Literal["zip", "directory", "unknown"] = "unknown"
    archive_sha256: str | None = None
    package_sha256: str | None = None
    # Directory identity is a Lab inventory digest, never an original vendor ZIP hash.
    package_digest_algorithm: str = "sha256-lab-sorted-file-inventory-v1"
    observed_main: int | None = None
    observed_recovery: int | None = None
    expected_main: Literal[257] = 257
    expected_recovery: Literal[18] = 18
    observed_product: None = None
    reference_product: str = "SNOWSKY_DISC"
    reference_id: str = "v257-upstream-metadata"
    reference_sha256: str | None = None
    reference_source_commit: str = "85ab00deb08ac112066377fd8083cc8727ed859a"
    rootfs_reference_sha256: str | None = None
    rootfs_reference_bytes: int | None = None
    expected_chunk_count: int = 77
    chunk_count: int = 0
    chunks: list[ChunkIdentity] = Field(default_factory=list)
    metadata_hashes: dict[str, str] = Field(default_factory=dict)
    limits: dict[str, int] = Field(
        default_factory=lambda: {
            "archive_bytes": MAX_ARCHIVE_BYTES,
            "total_uncompressed_bytes": MAX_TOTAL_BYTES,
            "entries": MAX_ENTRIES,
            "member_bytes": MAX_MEMBER_BYTES,
            "rootfs_chunk_bytes": MAX_CHUNK_BYTES,
            "metadata_bytes": MAX_METADATA_BYTES,
            "compression_ratio": MAX_COMPRESSION_RATIO,
            "central_directory_bytes": MAX_DIRECTORY_BYTES,
            "path_bytes": MAX_PATH_BYTES,
            "path_depth": MAX_DEPTH,
            "cooperative_seconds": MAX_SECONDS,
        }
    )
    conditions: list[Condition] = Field(default_factory=list)
    inspected_files: int = 0
    inspected_bytes: int = 0
    inspection_complete: bool = False
    may_proceed: Literal[False] = False
    extraction_authorized: Literal[False] = False
    execution_authorized: Literal[False] = False
    compatibility: Literal["unverified"] = "unverified"
    vendor_authenticity: Literal["unverified"] = "unverified"


class Refusal(ValueError):
    """Only fixed diagnostic codes cross the receipt boundary."""


def _require(ok: bool, code: str) -> None:
    if not ok:
        raise Refusal(code)


def _linked(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    # Windows path/handle stat can disagree about ctime (birth versus change time).
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _components(path: Path) -> os.stat_result:
    for item in reversed((path, *path.parents)):
        info = item.lstat()
        _require(not _linked(info), "unsafe_link_or_reparse_point")
        if item != path:
            _require(stat.S_ISDIR(info.st_mode), "non_directory_parent")
    return path.lstat()


@contextmanager
def _open_regular(path: Path, expected: os.stat_result) -> Generator[IO[bytes]]:
    _require(stat.S_ISREG(expected.st_mode), "not_regular_file")
    _require(not _linked(expected), "unsafe_link_or_reparse_point")
    _require(expected.st_nlink == 1, "hard_link_unsupported")
    _require(_identity(_components(path)) == _identity(expected), "input_changed")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        _require(stat.S_ISREG(opened.st_mode), "not_regular_file")
        _require(_identity(opened) == _identity(expected), "input_changed")
        _require(_identity(_components(path)) == _identity(expected), "input_changed")
        # Unbuffered: a later ZIP rehash must observe the descriptor's bytes,
        # not reuse Python's earlier read buffer after a seek.
        with os.fdopen(descriptor, "rb", buffering=0) as stream:
            descriptor = -1
            yield stream
            _require(_identity(os.fstat(stream.fileno())) == _identity(expected), "input_changed")
            _require(_identity(_components(path)) == _identity(expected), "input_changed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _safe_name(name: str, *, directory: bool = False) -> str:
    _require("\x00" not in name and "\\" not in name, "unsafe_member_path")
    if directory and name.endswith("/"):
        name = name[:-1]
    _require(0 < len(name.encode("utf-8")) <= MAX_PATH_BYTES, "unsafe_member_path")
    parts = name.split("/")
    _require(len(parts) <= MAX_DEPTH, "path_depth_limit")
    for part in parts:
        _require(bool(SAFE_COMPONENT.fullmatch(part)), "unsafe_member_path")
        _require(part not in {".", ".."} and not part.endswith((".", " ")), "unsafe_member_path")
        _require(part.split(".")[0].casefold() not in RESERVED, "unsafe_member_path")
    return name


def _metadata(name: str) -> bool:
    return name.rsplit("/", 1)[-1] in {
        "ota_config.in",
        "manifest.sha256",
        "manifest.sha256.sig",
        "md5_file_info.txt",
    }


def _limit(name: str) -> int:
    if _metadata(name):
        return MAX_METADATA_BYTES
    if name.rsplit("/", 1)[-1].startswith("rootfs.squashfs."):
        return MAX_CHUNK_BYTES
    return MAX_MEMBER_BYTES


class _Inspection:
    def __init__(self) -> None:
        self.deadline = time.monotonic() + MAX_SECONDS
        self.files: dict[str, tuple[int, str]] = {}
        self.metadata: dict[str, bytes] = {}
        self.seen: dict[str, bool] = {}
        self.spelling: dict[str, str] = {}
        self.total = 0

    def tick(self) -> None:
        _require(time.monotonic() <= self.deadline, "inspection_time_limit")

    def register(self, raw: str, directory: bool) -> str:
        self.tick()
        name = _safe_name(raw, directory=directory)
        _require(len(self.seen) < MAX_ENTRIES, "entry_count_limit")
        key = name.casefold()
        _require(key not in self.seen, "duplicate_or_case_collision")
        # Also reject implicit directory aliases and file/parent conflicts.
        parts = name.split("/")
        for index in range(1, len(parts) + 1):
            prefix = "/".join(parts[:index])
            folded = prefix.casefold()
            prior = self.spelling.get(folded)
            _require(prior is None or prior == prefix, "duplicate_or_case_collision")
            self.spelling[folded] = prefix
            if index < len(parts):
                _require(self.seen.get(folded, True), "file_directory_collision")
        if not directory:
            _require(
                not any(p.startswith(key + "/") for p in self.seen), "file_directory_collision"
            )
        self.seen[key] = directory
        return name

    def consume(self, name: str, stream: IO[bytes], expected_size: int) -> None:
        self.tick()
        _require(0 <= expected_size <= _limit(name), "member_size_limit")
        _require(self.total + expected_size <= MAX_TOTAL_BYTES, "total_size_limit")
        digest = hashlib.sha256()
        count = 0
        captured = bytearray()
        prefix = b""
        while True:
            self.tick()
            block = stream.read(min(BLOCK_BYTES, _limit(name) - count + 1))
            if not block:
                break
            count += len(block)
            self.total += len(block)
            _require(count <= expected_size and count <= _limit(name), "member_size_limit")
            _require(self.total <= MAX_TOTAL_BYTES, "total_size_limit")
            digest.update(block)
            if len(prefix) < 512:
                prefix = (prefix + block)[:512]
            if _metadata(name):
                captured.extend(block)
        _require(count == expected_size, "member_size_mismatch")
        nested = prefix.startswith(
            (
                b"PK\x03\x04",
                b"PK\x05\x06",
                b"\x1f\x8b",
                b"BZh",
                b"\xfd7zXZ\x00",
                b"7z\xbc\xaf\x27\x1c",
                b"Rar!",
            )
        )
        nested = nested or prefix[257:262] == b"ustar"
        _require(
            not nested and Path(name).suffix.lower() not in ARCHIVE_SUFFIXES,
            "nested_archive_unsupported",
        )
        self.files[name] = (count, digest.hexdigest())
        if _metadata(name):
            self.metadata[name] = bytes(captured)


def _zip_preflight(stream: IO[bytes], size: int) -> int:
    _require(22 <= size <= MAX_ARCHIVE_BYTES, "archive_size_limit")
    stream.seek(max(0, size - 65557))
    tail = stream.read(65557)
    position = tail.rfind(b"PK\x05\x06")
    _require(position >= 0 and len(tail) - position >= 22, "invalid_zip_directory")
    _, disk, cd_disk, disk_entries, entries, cd_bytes, cd_offset, comment = struct.unpack_from(
        "<4s4H2IH", tail, position
    )
    _require(position + 22 + comment == len(tail), "zip_trailing_data")
    _require(disk == cd_disk == 0 and disk_entries == entries, "multipart_zip_unsupported")
    _require(
        entries != 0xFFFF and cd_offset != 0xFFFFFFFF and cd_bytes != 0xFFFFFFFF,
        "zip64_unsupported",
    )
    _require(0 < entries <= MAX_ENTRIES, "entry_count_limit")
    _require(cd_bytes <= MAX_DIRECTORY_BYTES, "zip_directory_size_limit")
    eocd = size - len(tail) + position
    _require(cd_offset + cd_bytes == eocd, "invalid_zip_directory")
    stream.seek(0)
    _require(stream.read(4) == b"PK\x03\x04", "zip_prefix_unsupported")
    stream.seek(0)
    return entries


def _inspect_zip(path: Path, info: os.stat_result, work: _Inspection) -> str:
    with _open_regular(path, info) as stream:
        entry_count = _zip_preflight(stream, info.st_size)
        digest = hashlib.sha256()
        hashed = 0
        while block := stream.read(BLOCK_BYTES):
            work.tick()
            hashed += len(block)
            _require(hashed <= info.st_size and hashed <= MAX_ARCHIVE_BYTES, "input_changed")
            digest.update(block)
        _require(hashed == info.st_size, "input_changed")
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive:
            members = archive.infolist()
            _require(0 < len(members) <= MAX_ENTRIES, "entry_count_limit")
            _require(len(members) == entry_count, "zip_entry_count_mismatch")
            declared = 0
            planned: list[tuple[zipfile.ZipInfo, str]] = []
            for member in members:
                _require(member.orig_filename == member.filename, "unsafe_member_path")
                mode = member.external_attr >> 16
                kind = stat.S_IFMT(mode)
                directory = member.is_dir()
                _require(
                    kind in ({0, stat.S_IFDIR} if directory else {0, stat.S_IFREG}),
                    "unsafe_zip_file_type",
                )
                _require(not member.external_attr & 0x400, "unsafe_zip_reparse_point")
                _require(not member.flag_bits & (1 | 64 | 8192), "encrypted_zip_unsupported")
                _require(not member.flag_bits & 8, "zip_data_descriptor_unsupported")
                _require(not member.flag_bits & ~0x806, "zip_flags_unsupported")
                _require(
                    member.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED},
                    "zip_compression_unsupported",
                )
                # Extra fields can encode links/ZIP64 or alternate platform metadata.
                _require(not member.extra, "zip_extra_fields_unsupported")
                name = work.register(member.filename, directory)
                _require(member.file_size <= _limit(name), "member_size_limit")
                declared += member.file_size
                _require(declared <= MAX_TOTAL_BYTES, "total_size_limit")
                _require(
                    member.file_size <= max(1, member.compress_size) * MAX_COMPRESSION_RATIO,
                    "compression_ratio_limit",
                )
                if directory:
                    _require(
                        member.file_size == member.compress_size == member.CRC == 0,
                        "invalid_directory_member",
                    )
                planned.append((member, name))
            # zipfile checks local header names, overlapping entries and stream CRCs.
            for member, name in planned:
                stream.seek(member.header_offset)
                header = stream.read(30)
                _require(len(header) == 30 and header[:4] == b"PK\x03\x04", "invalid_local_header")
                fields = struct.unpack("<4s5H3I2H", header)
                flags, method = fields[2:4]
                name_bytes, extra_bytes = fields[-2:]
                _require(
                    flags == member.flag_bits and method == member.compress_type,
                    "inconsistent_local_header",
                )
                _require(
                    name_bytes <= MAX_PATH_BYTES and extra_bytes == 0,
                    "zip_extra_fields_unsupported",
                )
                encoding = "utf-8" if flags & 0x800 else "cp437"
                _require(
                    stream.read(name_bytes).decode(encoding) == member.filename,
                    "inconsistent_local_header",
                )
                if not flags & 8:
                    _require(
                        fields[6:9] == (member.CRC, member.compress_size, member.file_size),
                        "inconsistent_local_header",
                    )
                with archive.open(member) as content:
                    if member.is_dir():
                        _require(content.read(1) == b"", "invalid_directory_member")
                    else:
                        work.consume(name, content, member.file_size)
        # Detect content changes even if the writer restored timestamps. A hostile
        # owner racing/restoring bytes between observations remains outside this boundary.
        stream.seek(0)
        final_digest = hashlib.sha256()
        checked = 0
        while block := stream.read(BLOCK_BYTES):
            work.tick()
            checked += len(block)
            _require(checked <= info.st_size, "input_changed")
            final_digest.update(block)
        _require(
            checked == info.st_size and final_digest.digest() == digest.digest(), "input_changed"
        )
        return digest.hexdigest()


def _inspect_directory(path: Path, work: _Inspection) -> None:
    states: list[tuple[Path, os.stat_result]] = []

    def visit(directory: Path, prefix: str, expected: os.stat_result) -> None:
        work.tick()
        _require(_identity(_components(directory)) == _identity(expected), "input_changed")
        states.append((directory, expected))
        with os.scandir(directory) as entries:
            for entry in entries:
                work.tick()
                # Windows DirEntry.stat may omit st_dev/st_ino; use full lstat IDs.
                child = directory / entry.name
                info = child.lstat()
                _require(not _linked(info), "unsafe_link_or_reparse_point")
                is_dir = stat.S_ISDIR(info.st_mode)
                _require(is_dir or stat.S_ISREG(info.st_mode), "not_regular_file")
                name = work.register(prefix + entry.name, is_dir)
                if is_dir:
                    visit(child, name + "/", info)
                else:
                    with _open_regular(child, info) as stream:
                        work.consume(name, stream, info.st_size)
                    states.append((child, info))

    visit(path, "", _components(path))
    for item, previous in states:
        work.tick()
        _require(_identity(_components(item)) == _identity(previous), "input_changed")


def _text(data: bytes) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refusal("invalid_metadata_encoding") from None
    _require("\x00" not in text and not text.startswith("\ufeff"), "invalid_metadata_encoding")
    return text


def _versions(data: bytes) -> tuple[int, int]:
    values: dict[str, int] = {}
    for line in _text(data).splitlines():
        if not line:
            continue
        match = re.fullmatch(r"(current_version|recovery_version)=([1-9][0-9]{0,5})", line)
        _require(match is not None, "unsupported_or_malformed_config")
        assert match is not None
        _require(match[1] not in values, "duplicate_metadata")
        values[match[1]] = int(match[2])
    _require(set(values) == {"current_version", "recovery_version"}, "missing_version_metadata")
    return values["current_version"], values["recovery_version"]


def _structure(work: _Inspection, details: dict[str, object]) -> None:
    configs = [p for p in work.files if p.rsplit("/", 1)[-1] == "ota_config.in"]
    _require(len(configs) == 1, "missing_or_ambiguous_package_config")
    config = configs[0]
    prefix = config.removesuffix("ota_config.in")
    # A ZIP may have one wrapper folder; never guess arbitrary nested roots.
    _require(not prefix or prefix.count("/") == 1, "unsupported_package_layout")
    _require(all(p.startswith(prefix) for p in work.files), "ambiguous_package_roots")
    main, recovery = _versions(work.metadata[config])
    details.update(observed_main=main, observed_recovery=recovery)
    _require((main, recovery) == (257, 18), "unknown_firmware_reference")
    ota = prefix + "main_os/ota_v257/"
    manifest_path = ota + "manifest.sha256"
    _require(manifest_path in work.metadata, "missing_manifest")
    metadata_hashes = {
        "ota_config": work.files[config][1],
        "main_manifest": work.files[manifest_path][1],
    }
    signature = ota + "manifest.sha256.sig"
    if signature in work.files:
        metadata_hashes["main_signature"] = work.files[signature][1]
    details["metadata_hashes"] = metadata_hashes
    expected: dict[str, str] = {}
    for line in _text(work.metadata[manifest_path]).splitlines():
        _require(bool(line), "malformed_manifest")
        match = MANIFEST.fullmatch(line)
        _require(match is not None, "malformed_manifest")
        assert match is not None
        _safe_name(match[1])
        _require(match[1] not in expected, "duplicate_manifest_entry")
        expected[match[1]] = match[2]
    chunks: dict[int, ChunkIdentity] = {}
    actual_ota: set[str] = set()
    for path, (size, digest) in work.files.items():
        relative = path.removeprefix(prefix)
        if path.startswith(ota):
            name = path[len(ota) :]
            _require("/" not in name, "unsupported_package_layout")
            if name in {"manifest.sha256", "manifest.sha256.sig"}:
                continue
            _require(CHUNK.fullmatch(name) is not None, "unsupported_ota_member")
            _require(size > 0, "empty_rootfs_chunk")
            actual_ota.add(name)
            _require(expected.get(name) == digest, "chunk_checksum_mismatch")
            match = CHUNK.fullmatch(name)
            if name.startswith("rootfs.squashfs."):
                _require(match is not None, "malformed_chunk_name")
            if match:
                index = int(match[1])
                _require(index not in chunks, "duplicate_chunk_index")
                chunks[index] = ChunkIdentity(
                    index=index,
                    size=size,
                    sha256=digest,
                    manifest_sha256=expected[name],
                    filename_hash=match[2],
                )
        elif relative not in {"ota_config.in", "md5_file_info.txt"}:
            # Recovery payload is inventoried only; it is not a verified recovery image.
            _require(
                relative.startswith("recovery/ota_v18/")
                and relative.endswith((".enc", "/manifest.sha256", "/manifest.sha256.sig")),
                "unsupported_package_member",
            )
    details.update(chunk_count=len(chunks), chunks=[chunks[i] for i in sorted(chunks)])
    _require(set(expected) == actual_ota, "manifest_membership_mismatch")
    _require(set(chunks) == set(range(77)), "rootfs_chunk_structure_mismatch")


def inspect_firmware(path: Path) -> IntakeReceipt:
    """Inspect one local candidate. An accepted receipt grants no next-stage authority."""
    work = _Inspection()
    details: dict[str, object] = {}
    conditions = [
        Condition(check="vendor_authenticity", status="unverified", code="no_reviewed_trust_chain"),
        Condition(check="product", status="unverified", code="not_observable_at_intake"),
        Condition(check="plaintext_rootfs", status="unverified", code="decryption_not_performed"),
        Condition(check="stock_binaries", status="unverified", code="extraction_not_performed"),
        Condition(
            check="chunk_length_consistency",
            status="unverified",
            code="vendor_length_rule_unestablished",
        ),
        Condition(
            check="signature_verification", status="unsupported", code="trust_anchor_unresolved"
        ),
        Condition(check="recovery_payload", status="unverified", code="inventory_only"),
        Condition(check="md5_metadata", status="unsupported", code="not_used_as_authenticity"),
        Condition(
            check="filename_hash_meaning", status="unverified", code="not_ciphertext_assertion"
        ),
        Condition(check="execution", status="unsupported", code="outside_intake_scope"),
    ]
    try:
        # First-party data-only reference; no upstream imports or source cache access.
        from snowsky_disc_lab.firmware_reference import load_reference

        reference = load_reference()
        # The loader interface is kept isolated here from inspection mechanics.
        details.update(
            reference_sha256=reference.sha256,
            rootfs_reference_sha256=reference.metadata.rootfs_sha256,
            rootfs_reference_bytes=reference.metadata.rootfs_size,
        )
        selected = Path(os.path.abspath(path))
        # Do not probe UNC shares or Windows device namespaces as local firmware.
        raw_path = os.fspath(path)
        _require(not raw_path.startswith(("\\\\", "//", "\\??\\")), "nonlocal_input_unsupported")
        _require(not re.match(r"^[A-Za-z]:[^\\/]", raw_path), "drive_relative_input_unsupported")
        info = _components(selected)
        if stat.S_ISDIR(info.st_mode):
            details["input_format"] = "directory"
            _inspect_directory(selected, work)
        elif stat.S_ISREG(info.st_mode):
            details["input_format"] = "zip"
            details["archive_sha256"] = _inspect_zip(selected, info, work)
        else:
            raise Refusal("unsupported_input_type")
        inventory = [[name, size, digest] for name, (size, digest) in sorted(work.files.items())]
        details["package_sha256"] = hashlib.sha256(
            json.dumps(inventory, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        details["inspection_complete"] = True
        conditions.append(
            Condition(check="input_safety", status="verified", code="bounded_inventory")
        )
        _structure(work, details)
        conditions.append(
            Condition(
                check="structure_and_integrity",
                status="verified",
                code="v257_indices_and_manifest_hashes",
            )
        )
        details["status"] = "accepted"
    except Refusal as error:
        conditions.append(Condition(check="intake", status="rejected", code=str(error)))
    except (
        OSError,
        ValueError,
        RuntimeError,
        zipfile.BadZipFile,
        NotImplementedError,
        EOFError,
        struct.error,
        zlib.error,
    ):
        # Never echo paths, metadata, archive comments or exception strings.
        conditions.append(
            Condition(check="intake", status="rejected", code="unreadable_or_invalid_input")
        )
    details.update(
        inspected_files=len(work.files), inspected_bytes=work.total, conditions=conditions
    )
    if details.get("status") != "accepted":
        conditions.append(
            Condition(
                check="structure_and_integrity", status="unverified", code="inspection_not_accepted"
            )
        )
    return IntakeReceipt.model_validate(details)
