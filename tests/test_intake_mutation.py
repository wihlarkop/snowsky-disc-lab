"""A receipt must refuse observed content changes even when timestamps are restored."""

from __future__ import annotations

import io
import os
import runpy
import struct
import zipfile
from pathlib import Path
from typing import IO

import pytest

from snowsky_disc_lab import firmware_intake


def test_zip_rehash_refuses_same_size_timestamp_restored_rewrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helpers = runpy.run_path(str(Path(__file__).with_name("test_firmware_intake.py")))
    package, _ = helpers["_make_package"](tmp_path / "synthetic-package")
    archive = helpers["_zip_package"](package, tmp_path / "synthetic.zip")
    original = archive.stat()
    consume = firmware_intake._Inspection.consume
    changed = False

    def mutate_after_read(
        self: firmware_intake._Inspection, name: str, stream: IO[bytes], expected_size: int
    ) -> None:
        nonlocal changed
        consume(self, name, stream, expected_size)
        if not changed:
            # Local timestamp metadata does not alter payload/CRC/name checks.
            with archive.open("r+b") as target:
                target.seek(10)
                value = target.read(1)
                target.seek(10)
                target.write(bytes([value[0] ^ 1]))
            os.utime(archive, ns=(original.st_atime_ns, original.st_mtime_ns))
            changed = True

    monkeypatch.setattr(firmware_intake._Inspection, "consume", mutate_after_read)
    receipt = firmware_intake.inspect_firmware(archive)
    assert changed
    assert receipt.status == "refused"
    assert any(condition.code == "input_changed" for condition in receipt.conditions)


def test_unc_input_is_refused_without_filesystem_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object) -> None:
        pytest.fail("UNC inputs must be refused before any filesystem probe")

    monkeypatch.setattr(firmware_intake, "_components", forbidden)
    receipt = firmware_intake.inspect_firmware(Path("//not-a-real-server/synthetic.zip"))
    assert receipt.status == "refused"
    assert any(condition.code == "nonlocal_input_unsupported" for condition in receipt.conditions)


@pytest.mark.parametrize("hidden_record", [False, True])
def test_zip_refuses_unindexed_bytes_or_local_records(tmp_path: Path, hidden_record: bool) -> None:
    helpers = runpy.run_path(str(Path(__file__).with_name("test_firmware_intake.py")))
    package, _ = helpers["_make_package"](tmp_path / "synthetic-package")
    archive = helpers["_zip_package"](package, tmp_path / "unindexed.zip")
    raw = archive.read_bytes()
    eocd = raw.rfind(b"PK\x05\x06")
    central = struct.unpack_from("<I", raw, eocd + 16)[0]
    hidden = b"synthetic unindexed gap"
    if hidden_record:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as output:
            output.writestr("../unindexed-synthetic-member", b"synthetic only")
        isolated = buffer.getvalue()
        isolated_eocd = isolated.rfind(b"PK\x05\x06")
        isolated_central = struct.unpack_from("<I", isolated, isolated_eocd + 16)[0]
        hidden = isolated[:isolated_central]
    modified = bytearray(raw[:central] + hidden + raw[central:])
    struct.pack_into("<I", modified, eocd + len(hidden) + 16, central + len(hidden))
    archive.write_bytes(modified)
    receipt = firmware_intake.inspect_firmware(archive)
    assert receipt.status == "refused"
    assert any(condition.code == "unindexed_zip_bytes" for condition in receipt.conditions)
