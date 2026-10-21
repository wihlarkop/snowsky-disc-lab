"""Generated ELF fixtures exercise offline inspection without executing binaries."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest

from snowsky_disc_lab.elf_inspection import ElfInspectionError, inspect_elf


def _elf32_mips(
    *,
    dynamic: bool = False,
    interpreter: bytes | None = None,
    needed: tuple[str, ...] = (),
    fp_abi: int | None = None,
    flags: int = 0x1000,
    file_type: int = 2,
    machine: int = 8,
    load: bytes | None = None,
) -> bytes:
    """Build a tiny first-party ELF32 little-endian MIPS fixture."""
    endian = "<"
    ident = b"\x7fELF" + bytes((1, 1, 1, 0)) + bytes(8)
    header_size, ph_size = 52, 32
    names = b"\0" + b"\0".join(name.encode() for name in needed) + (b"\0" if needed else b"")
    phnum = (
        int(load is not None)
        + int(interpreter is not None)
        + (2 if dynamic else 0)
        + int(fp_abi is not None)
    )
    cursor = header_size + phnum * ph_size
    segments: list[tuple[int, int, int, bytes]] = []
    if load is not None:
        segments.append((1, cursor, 0x10000 + cursor, load))
        cursor += len(load)
    if interpreter is not None:
        data = interpreter + (b"" if interpreter.endswith(b"\0") else b"\0")
        segments.append((3, cursor, 0x10000 + cursor, data))
        cursor += len(data)
    if dynamic:
        dynamic_offset = cursor
        cursor += 64
        string_offset = cursor
        dynamic_entries = [(5, 0x10000 + string_offset), (10, len(names))]
        string_at = 1
        for name in needed:
            dynamic_entries.append((1, string_at))
            string_at += len(name.encode()) + 1
        dynamic_entries.append((0, 0))
        dyn = b"".join(struct.pack(endian + "iI", tag, value) for tag, value in dynamic_entries)
        dyn += bytes(64 - len(dyn))
        segments.extend(
            [
                (2, dynamic_offset, 0x10000 + dynamic_offset, dyn),
                (1, string_offset, 0x10000 + string_offset, names),
            ]
        )
        cursor += len(names)
    if fp_abi is not None:
        abi = struct.pack(endian + "H6B4I", 0, 32, 1, 1, 0, 0, fp_abi, 0, 0, 0, 0)
        segments.append((0x70000003, cursor, 0x10000 + cursor, abi))
        cursor += len(abi)
    header = struct.pack(
        endian + "16sHHIIIIIHHHHHH",
        ident,
        file_type,
        machine,
        1,
        0,
        header_size if phnum else 0,
        0,
        flags,
        header_size,
        ph_size if phnum else 0,
        phnum,
        40,
        0,
        0,
    )
    output = bytearray(cursor)
    output[:header_size] = header
    for index, (p_type, offset, vaddr, data) in enumerate(segments):
        phdr = struct.pack(
            endian + "IIIIIIII",
            p_type,
            offset,
            vaddr,
            vaddr,
            len(data),
            len(data),
            5,
            4,
        )
        start = header_size + index * ph_size
        output[start : start + ph_size] = phdr
        output[offset : offset + len(data)] = data
    return bytes(output)


def _write(tmp_path: Path, data: bytes, name: str = "synthetic-ui") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_inspects_mips_identity_hash_and_unknown_compatibility(tmp_path: Path) -> None:
    data = _elf32_mips()
    path = _write(tmp_path, data)

    report = inspect_elf(path)

    assert report.path == path
    assert report.file_name == path.name
    assert report.size_bytes == len(data)
    assert report.sha256 == hashlib.sha256(data).hexdigest()
    assert report.elf_class == "ELF32"
    assert report.endianness == "little"
    assert report.machine == "MIPS"
    assert report.static_dynamic == "UNKNOWN"
    assert report.interpreter is None
    assert report.float_abi == "UNKNOWN"
    assert report.compatibility == "UNKNOWN"
    assert report.mips_flags == 0x1000
    assert report.mips_abi == "O32"


def test_reads_interpreter_and_dynamic_needed_libraries(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        _elf32_mips(
            dynamic=True,
            interpreter=b"/lib/ld.so.1",
            needed=("libc.so.6", "libui.so"),
        ),
    )

    report = inspect_elf(path)

    assert report.static_dynamic == "dynamic"
    assert report.interpreter == "/lib/ld.so.1"
    assert report.needed_libraries == ("libc.so.6", "libui.so")
    assert report.float_abi == "UNKNOWN"


def test_reads_mips_soft_float_from_abi_flags_segment(tmp_path: Path) -> None:
    report = inspect_elf(_write(tmp_path, _elf32_mips(fp_abi=3)))

    assert report.float_abi == "soft"


def test_refuses_truncated_header_and_program_segment(tmp_path: Path) -> None:
    with pytest.raises(ElfInspectionError, match="truncated"):
        inspect_elf(_write(tmp_path, b"\x7fELF"))

    malformed = bytearray(_elf32_mips(interpreter=b"/lib/ld.so.1"))
    malformed[56:60] = struct.pack("<I", 0xFFFFFFF0)
    with pytest.raises(ElfInspectionError, match="outside"):
        inspect_elf(_write(tmp_path, bytes(malformed), "bad-segment"))


def test_rejects_unterminated_interpreter(tmp_path: Path) -> None:
    data = bytearray(_elf32_mips(interpreter=b"/lib/ld.so.1"))
    data[-1] = ord("x")
    with pytest.raises(ElfInspectionError, match="NUL"):
        inspect_elf(_write(tmp_path, bytes(data)))


def test_rejects_invalid_dynamic_string_reference(tmp_path: Path) -> None:
    data = bytearray(_elf32_mips(dynamic=True, needed=("libc.so.6",)))
    # PT_DYNAMIC is the first program segment in this fixture.
    dynamic_offset = struct.unpack_from("<I", data, 52 + 4)[0]
    data[dynamic_offset + 20 : dynamic_offset + 24] = struct.pack("<I", 0xFFFF)

    with pytest.raises(ElfInspectionError, match="string"):
        inspect_elf(_write(tmp_path, bytes(data)))


def test_rejects_non_elf_and_oversized_inputs(tmp_path: Path) -> None:
    with pytest.raises(ElfInspectionError, match="ELF magic"):
        inspect_elf(_write(tmp_path, b"not an elf"))

    with pytest.raises(ElfInspectionError, match="size limit"):
        inspect_elf(_write(tmp_path, b"\x7fELF" + bytes(128), "too-large"), max_bytes=16)


def test_inspects_elf64_big_endian_fixture(tmp_path: Path) -> None:
    ident = b"\x7fELF" + bytes((2, 2, 1, 0)) + bytes(8)
    header = struct.pack(">16sHHIQQQIHHHHHH", ident, 2, 62, 1, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0)
    report = inspect_elf(_write(tmp_path, header, "synthetic-elf64"))

    assert report.elf_class == "ELF64"
    assert report.endianness == "big"
    assert report.machine == "AMD x86-64"
    assert report.mips_abi == "UNKNOWN"
    assert report.mips_flags is None


def test_refuses_dynamic_table_without_terminator(tmp_path: Path) -> None:
    data = bytearray(_elf32_mips(dynamic=True))
    dynamic_offset = struct.unpack_from("<I", data, 52 + 4)[0]
    data[dynamic_offset : dynamic_offset + 64] = b"".join(
        struct.pack("<iI", 1, 0) for _ in range(8)
    )

    with pytest.raises(ElfInspectionError, match="DT_NULL"):
        inspect_elf(_write(tmp_path, bytes(data)))


def test_reads_mips_hard_float_from_o32_abi_flags(tmp_path: Path) -> None:
    report = inspect_elf(_write(tmp_path, _elf32_mips(fp_abi=1)))

    assert report.float_abi == "hard"


def test_rejects_input_limit_above_hard_cap(tmp_path: Path) -> None:
    path = _write(tmp_path, _elf32_mips())

    with pytest.raises(ElfInspectionError, match="hard safety limit"):
        inspect_elf(path, max_bytes=128 * 1024 * 1024 + 1)


def test_rejects_invalid_identification_and_header_versions(tmp_path: Path) -> None:
    invalid_ident_version = bytearray(_elf32_mips())
    invalid_ident_version[6] = 0
    with pytest.raises(ElfInspectionError, match="identification version"):
        inspect_elf(_write(tmp_path, bytes(invalid_ident_version), "bad-ident-version"))

    invalid_header_version = bytearray(_elf32_mips())
    invalid_header_version[20:24] = struct.pack("<I", 2)
    with pytest.raises(ElfInspectionError, match="ELF version"):
        inspect_elf(_write(tmp_path, bytes(invalid_header_version), "bad-header-version"))


def test_non_linked_object_has_unknown_linkage_classification(tmp_path: Path) -> None:
    report = inspect_elf(_write(tmp_path, _elf32_mips(file_type=1)))

    assert report.file_type == "relocatable"
    assert report.static_dynamic == "UNKNOWN"


def test_contradictory_mips_abi_flags_remain_unknown(tmp_path: Path) -> None:
    report = inspect_elf(_write(tmp_path, _elf32_mips(flags=0x1020)))

    assert report.mips_abi == "UNKNOWN"


def test_rejects_mips_abiflags_segment_on_non_mips(tmp_path: Path) -> None:
    with pytest.raises(ElfInspectionError, match="non-MIPS"):
        inspect_elf(_write(tmp_path, _elf32_mips(fp_abi=3, machine=62)))


def test_rejects_program_segment_file_size_larger_than_memory_size(tmp_path: Path) -> None:
    malformed = bytearray(_elf32_mips(interpreter=b"/lib/ld.so.1"))
    # The first program header's p_memsz field follows p_filesz.
    malformed[52 + 20 : 52 + 24] = struct.pack("<I", 0)

    with pytest.raises(ElfInspectionError, match="p_filesz"):
        inspect_elf(_write(tmp_path, bytes(malformed)))


def test_classifies_linked_executable_without_dynamic_metadata_as_static(tmp_path: Path) -> None:
    report = inspect_elf(_write(tmp_path, _elf32_mips(load=b"synthetic-code")))

    assert report.static_dynamic == "static"
