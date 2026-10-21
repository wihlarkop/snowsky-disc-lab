"""Bounded, offline ELF metadata inspection; this module never loads inspected code."""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from pathlib import Path

_MAX_BYTES = 128 * 1024 * 1024
_MAX_PROGRAM_HEADERS = 4096
_MAX_DYNAMIC_ENTRIES = 1_000_000
_PT_LOAD = 1
_PT_DYNAMIC = 2
_PT_INTERP = 3
_PT_MIPS_ABIFLAGS = 0x70000003
_DT_NULL = 0
_DT_NEEDED = 1
_DT_STRTAB = 5
_DT_STRSZ = 10
_MIPS_ABI_MASK = 0xF000
_MIPS_ABI_NAMES = {
    0x1000: "O32",
    0x2000: "O64",
    0x3000: "EABI32",
    0x4000: "EABI64",
}
_MACHINE_NAMES = {
    3: "Intel 80386",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    40: "ARM",
    62: "AMD x86-64",
    183: "AArch64",
    243: "RISC-V",
}


class ElfInspectionError(ValueError):
    """Raised when a selected file is not a safely parseable ELF object."""


@dataclass(frozen=True, slots=True)
class ElfInspection:
    """Read-only summary of a local ELF file's declared metadata."""

    path: Path
    file_name: str
    size_bytes: int
    sha256: str
    elf_class: str
    endianness: str
    machine: str
    machine_id: int
    file_type: str
    static_dynamic: str
    interpreter: str | None
    needed_libraries: tuple[str, ...]
    mips_abi: str
    mips_flags: int | None
    mips_abiflags_present: bool
    float_abi: str
    compatibility: str


def inspect_elf(path: str | os.PathLike[str], *, max_bytes: int = _MAX_BYTES) -> ElfInspection:
    """Inspect a local ELF byte stream without executing or modifying it.

    ``max_bytes`` bounds the input read. ELF tables and dynamic strings are
    checked against both that buffer and their declared segment lengths.
    """
    selected = Path(path)
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    if max_bytes > _MAX_BYTES:
        raise ElfInspectionError("max_bytes exceeds hard safety limit")
    try:
        with selected.open("rb") as source:
            raw = source.read(max_bytes + 1)
    except OSError as error:
        raise ElfInspectionError(
            f"cannot read selected ELF file: {error.strerror or 'I/O error'}"
        ) from None
    if len(raw) > max_bytes:
        raise ElfInspectionError("input exceeds configured size limit")
    if raw[:4] != b"\x7fELF":
        raise ElfInspectionError("invalid ELF magic")
    if len(raw) < 16:
        raise ElfInspectionError("truncated ELF identification header")
    elf_class_id, data_id = raw[4], raw[5]
    if elf_class_id not in (1, 2):
        raise ElfInspectionError("unsupported ELF class")
    if data_id not in (1, 2):
        raise ElfInspectionError("unsupported ELF byte order")
    if raw[6] != 1:
        raise ElfInspectionError("unsupported ELF identification version")
    prefix = "<" if data_id == 1 else ">"
    elf_class = "ELF32" if elf_class_id == 1 else "ELF64"
    endian = "little" if data_id == 1 else "big"
    if elf_class_id == 1:
        header_format = prefix + "HHIIIIIHHHHHH"
        ph_format = prefix + "IIIIIIII"
        header_size, ph_min_size = 52, 32
    else:
        header_format = prefix + "HHIQQQIHHHHHH"
        ph_format = prefix + "IIQQQQQQ"
        header_size, ph_min_size = 64, 56
    if len(raw) < header_size:
        raise ElfInspectionError("truncated ELF header")
    fields = struct.unpack_from(header_format, raw, 16)
    e_type, machine_id, version = fields[0], fields[1], fields[2]
    if version != 1:
        raise ElfInspectionError("unsupported ELF version")
    if elf_class_id == 1:
        phoff, flags, ehsize, phentsize, phnum = (
            fields[4],
            fields[6],
            fields[7],
            fields[8],
            fields[9],
        )
    else:
        phoff, flags, ehsize, phentsize, phnum = (
            fields[4],
            fields[6],
            fields[7],
            fields[8],
            fields[9],
        )
    if ehsize < header_size:
        raise ElfInspectionError("invalid ELF header size")
    if ehsize > len(raw):
        raise ElfInspectionError("truncated ELF header")
    if phnum == 0xFFFF:
        raise ElfInspectionError("extended program header counts are unsupported")
    if phnum > _MAX_PROGRAM_HEADERS:
        raise ElfInspectionError("program header count exceeds safety limit")
    if phnum and phentsize < ph_min_size:
        raise ElfInspectionError("invalid program header entry size")
    if not phnum and (phoff != 0 or phentsize != 0):
        raise ElfInspectionError("program header offset and count contradict")
    if phnum and phoff < ehsize:
        raise ElfInspectionError("program header table overlaps the ELF header")
    table_end = phoff + phnum * phentsize
    if table_end > len(raw):
        raise ElfInspectionError("program header table is outside the file or truncated")

    segments: list[tuple[int, int, int, int]] = []
    for index in range(phnum):
        position = phoff + index * phentsize
        values = struct.unpack_from(ph_format, raw, position)
        if elf_class_id == 1:
            p_type, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_flags, _p_align = values
        else:
            p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = values
        p_memsz = values[5] if elf_class_id == 1 else values[6]
        if p_filesz > p_memsz:
            raise ElfInspectionError("program segment p_filesz exceeds p_memsz")
        if p_offset + p_filesz > len(raw):
            raise ElfInspectionError("program segment is outside the file or truncated")
        segments.append((p_type, p_offset, p_vaddr, p_filesz))

    if machine_id != 8 and any(segment[0] == _PT_MIPS_ABIFLAGS for segment in segments):
        raise ElfInspectionError("PT_MIPS_ABIFLAGS is invalid on a non-MIPS ELF")
    has_linkage_segment = any(segment[0] in (_PT_INTERP, _PT_DYNAMIC) for segment in segments)
    if has_linkage_segment and e_type not in (2, 3):
        raise ElfInspectionError("linkage segments contradict ELF file type")

    interpreters = [segment for segment in segments if segment[0] == _PT_INTERP]
    if len(interpreters) > 1:
        raise ElfInspectionError("multiple PT_INTERP segments are ambiguous")
    interpreter: str | None = None
    if interpreters:
        _, offset, _vaddr, size = interpreters[0]
        chunk = raw[offset : offset + size]
        terminator = chunk.find(b"\0")
        if terminator < 0 or terminator != len(chunk) - 1:
            raise ElfInspectionError("PT_INTERP must contain exactly one trailing NUL")
        if terminator == 0:
            raise ElfInspectionError("PT_INTERP path is empty")
        try:
            interpreter = chunk[:-1].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise ElfInspectionError("PT_INTERP path is not valid UTF-8") from None

    dynamic_segments = [segment for segment in segments if segment[0] == _PT_DYNAMIC]
    if len(dynamic_segments) > 1:
        raise ElfInspectionError("multiple PT_DYNAMIC segments are ambiguous")
    needed: tuple[str, ...] = ()
    if dynamic_segments:
        _, offset, _vaddr, size = dynamic_segments[0]
        entry_size = 8 if elf_class_id == 1 else 16
        if size % entry_size:
            raise ElfInspectionError("PT_DYNAMIC has a truncated entry")
        if size // entry_size > _MAX_DYNAMIC_ENTRIES:
            raise ElfInspectionError("dynamic entry count exceeds safety limit")
        tags: list[tuple[int, int]] = []
        terminated = False
        for position in range(offset, offset + size, entry_size):
            if elf_class_id == 1:
                tag, value = struct.unpack_from(prefix + "iI", raw, position)
            else:
                tag, value = struct.unpack_from(prefix + "qQ", raw, position)
            if tag == _DT_NULL:
                terminated = True
                break
            tags.append((tag, value))
        if not terminated:
            raise ElfInspectionError("PT_DYNAMIC is missing DT_NULL terminator")
        needed_offsets = [value for tag, value in tags if tag == _DT_NEEDED]
        strtabs = [value for tag, value in tags if tag == _DT_STRTAB]
        str_sizes = [value for tag, value in tags if tag == _DT_STRSZ]
        if needed_offsets:
            if len(strtabs) != 1 or len(str_sizes) != 1:
                raise ElfInspectionError(
                    "DT_NEEDED requires one unambiguous DT_STRTAB and DT_STRSZ"
                )
            string_data = _map_virtual_range(segments, strtabs[0], str_sizes[0], raw)
            names: list[str] = []
            for string_offset in needed_offsets:
                if string_offset >= len(string_data):
                    raise ElfInspectionError("DT_NEEDED string offset is outside DT_STRSZ")
                end = string_data.find(b"\0", string_offset)
                if end < 0:
                    raise ElfInspectionError("DT_NEEDED string is not NUL-terminated")
                try:
                    name = string_data[string_offset:end].decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    raise ElfInspectionError("DT_NEEDED string is not valid UTF-8") from None
                if not name:
                    raise ElfInspectionError("DT_NEEDED string is empty")
                names.append(name)
            needed = tuple(names)

    abi_segments = [segment for segment in segments if segment[0] == _PT_MIPS_ABIFLAGS]
    if len(abi_segments) > 1:
        raise ElfInspectionError("multiple PT_MIPS_ABIFLAGS segments are ambiguous")
    float_abi = "UNKNOWN"
    if machine_id == 8 and abi_segments:
        _type, offset, _vaddr, size = abi_segments[0]
        if size < 24:
            raise ElfInspectionError("truncated PT_MIPS_ABIFLAGS structure")
        version = struct.unpack_from(prefix + "H", raw, offset)[0]
        if version == 0:
            fp_abi_code = raw[offset + 7]
            if fp_abi_code == 3:
                float_abi = "soft"
            elif fp_abi_code in {1, 2}:
                float_abi = "hard"

    mips_abi = "UNKNOWN"
    mips_flags: int | None = None
    if machine_id == 8:
        mips_flags = flags
        abi_field = flags & _MIPS_ABI_MASK
        abi2 = bool(flags & 0x20)
        if abi2 and abi_field:
            mips_abi = "UNKNOWN"
        elif abi2:
            mips_abi = "N32"
        else:
            mips_abi = _MIPS_ABI_NAMES.get(abi_field, "UNKNOWN")
    file_type = {1: "relocatable", 2: "executable", 3: "shared-object", 4: "core"}.get(
        e_type, "unknown"
    )
    return ElfInspection(
        path=selected,
        file_name=selected.name,
        size_bytes=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
        elf_class=elf_class,
        endianness=endian,
        machine=_MACHINE_NAMES.get(machine_id, "UNKNOWN"),
        machine_id=machine_id,
        file_type=file_type,
        static_dynamic=(
            "dynamic"
            if interpreters or needed
            else "UNKNOWN"
            if dynamic_segments
            else "static"
            if e_type == 2 and any(segment[0] == _PT_LOAD for segment in segments)
            else "UNKNOWN"
        ),
        interpreter=interpreter,
        needed_libraries=needed,
        mips_abi=mips_abi if machine_id == 8 else "UNKNOWN",
        mips_flags=mips_flags,
        mips_abiflags_present=bool(abi_segments),
        float_abi=float_abi,
        compatibility="UNKNOWN",
    )


def _map_virtual_range(
    segments: list[tuple[int, int, int, int]], address: int, size: int, raw: bytes
) -> bytes:
    if size > len(raw):
        raise ElfInspectionError("DT_STRSZ exceeds the input size limit")
    for p_type, offset, vaddr, filesz in segments:
        if p_type == _PT_LOAD and vaddr <= address and address + size <= vaddr + filesz:
            file_offset = offset + address - vaddr
            return raw[file_offset : file_offset + size]
    raise ElfInspectionError("DT_STRTAB is not backed by a bounded PT_LOAD segment")


__all__ = ["ElfInspection", "ElfInspectionError", "inspect_elf"]
