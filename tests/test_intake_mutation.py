"""A receipt must refuse observed content changes even when timestamps are restored."""

from __future__ import annotations

import os
import runpy
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
