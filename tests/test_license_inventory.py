from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from snowsky_disc_lab.source_lock import load_source_lock

ROOT = Path(__file__).resolve().parents[1]


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    path: str
    sha256: str
    url: str


class InventoryRow(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    sourceId: str
    commit: str
    component: str
    paths: list[str] = Field(min_length=1)
    spdxExpression: str
    evidence: list[Evidence] = Field(min_length=1)
    reviewStatus: Literal["identified", "pending"]
    notes: str


class SourceIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    sourceId: str
    commit: str


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    formatVersion: Literal[1]
    reviewedOn: str
    sources: list[SourceIdentity] = Field(min_length=1)
    inventoryRows: list[InventoryRow] = Field(min_length=1)


def _safe_relative_path(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        "\\" not in value
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
        and bool(path.parts)
    )


def test_inventory_metadata_matches_pinned_source_lock() -> None:
    payload = json.loads((ROOT / "docs" / "license-inventory.json").read_text(encoding="utf-8"))
    inventory = Inventory.model_validate(payload)
    lock = load_source_lock(ROOT / "upstreams.lock.yaml")
    locked = {source.id: source for source in lock.sources}
    metadata = {source.sourceId: source.commit for source in inventory.sources}

    assert metadata == {source_id: source.commit for source_id, source in locked.items()}
    assert {row.sourceId for row in inventory.inventoryRows} == set(locked)

    dejavufont = next(
        row
        for row in inventory.inventoryRows
        if row.component == "Boomshine embedded DejaVu glyph data"
    )
    assert dejavufont.sourceId == "disco"
    assert dejavufont.spdxExpression == "Bitstream-Vera"
    assert dejavufont.spdxExpression != "OFL-1.1"

    for row in inventory.inventoryRows:
        pin = locked[row.sourceId]
        assert row.commit == pin.commit
        assert row.component.strip()
        assert row.spdxExpression.strip()
        assert row.notes.strip()
        assert all(_safe_relative_path(path) for path in row.paths)
        for evidence in row.evidence:
            assert _safe_relative_path(evidence.path)
            assert re.fullmatch(r"[0-9a-f]{64}", evidence.sha256)
            assert evidence.url == (
                f"{pin.repository.removesuffix('.git')}/blob/{pin.commit}/{evidence.path}"
            )
