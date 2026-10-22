"""Read-only registry command acceptance and serialization boundary regressions."""

import json
import os

import pytest
from test_compat_registry import record
from typer.testing import CliRunner

from snowsky_disc_lab.cli import app
from snowsky_disc_lab.compat_registry import (
    MAX_REGISTRY_BYTES,
    CompatibilityRegistry,
    RegistryError,
    build_registry,
    parse_registry_json,
    registry_json,
)

runner = CliRunner()


def write_registry(tmp_path, records=()):
    path = tmp_path / "registry.json"
    path.write_text(registry_json(build_registry(records)), encoding="utf-8")
    return path


def invoke(path, command="list", *args):
    return runner.invoke(app, ["compat", command, str(path), *args])


def test_empty_registry_and_read_only_selection(tmp_path):
    path = write_registry(tmp_path)
    before = path.read_bytes()
    result = invoke(path, "list", "--format", "json")
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["records"] == []
    assert "No records." in invoke(path).output
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


def test_stable_order_exact_lookup_and_null_identity(tmp_path):
    records = [record("z", scenario_id="a"), record("Alpha", scenario_id="z", rootfs_sha256=None)]
    path = write_registry(tmp_path, records)
    first = invoke(path, "list", "--format", "json")
    assert first.exit_code == 0, first.output
    assert [item["record_id"] for item in json.loads(first.output)["records"]] == ["Alpha", "z"]
    path.write_text(registry_json(build_registry(reversed(records))), encoding="utf-8")
    assert first.output == invoke(path, "list", "--format", "json").output
    result = invoke(path, "show", "--id", "Alpha", "--format", "json")
    assert json.loads(result.output) == records[1].model_dump(mode="json")
    markdown = invoke(path, "show", "--id", "Alpha").output
    assert "| rootfs_sha256 | unknown |" in markdown
    assert "Support state: unknown" in markdown
    assert "Scenario outcome: PASS" in markdown
    assert records[1].identity.ui_binary_sha256 in markdown
    for missing in ("alpha", "Alpha ", "Al", "missing"):
        result = invoke(path, "show", "--id", missing)
        assert result.exit_code == 1, result.output
        assert missing not in result.output


@pytest.mark.parametrize(
    "document",
    [
        "{",
        '{"records":[],"records":[]}',
        '{"schema_version":"future","records":[]}',
        "[" * 2000,
        "x" * (MAX_REGISTRY_BYTES + 1),
    ],
    ids=["malformed", "duplicate", "version", "nested", "oversized"],
)
def test_invalid_json_is_sanitized(tmp_path, document):
    path = tmp_path / "bad.json"
    path.write_text(document, encoding="utf-8")
    result = invoke(path)
    assert result.exit_code == 2
    assert result.output == "Compatibility registry refused: invalid local path or registry data.\n"


@pytest.mark.parametrize("change", ["verified-emulator", "verified-device", "duplicate", "missing"])
def test_registry_cannot_launder_verified_states_or_contradictions(tmp_path, change):
    path = write_registry(tmp_path, [record()])
    payload = json.loads(path.read_text())
    if change == "duplicate":
        payload["records"].append(payload["records"][0])
    elif change == "missing":
        payload["records"][0]["identity"].pop("rootfs_sha256")
    else:
        payload["records"][0]["support_state"] = change
    path.write_text(json.dumps(payload))
    assert invoke(path).exit_code == 2


def test_markdown_untrusted_text_and_provenance(tmp_path):
    unsafe = "# heading\n- [click](javascript:bad) ![img](https://bad) <script> | `x` \x1b[31m"
    candidate = record("record", ui_source_revision=None)
    candidate = candidate.model_copy(update={"limitations": (unsafe,)})
    path = write_registry(tmp_path, [candidate])
    result = invoke(path)
    assert result.exit_code == 0, result.output
    assert "Upstream claims (declared; unauthenticated)" in result.output
    assert "Lab observations (declared; unauthenticated)" in result.output
    assert r"source\-claim" in result.output
    assert r"sanitized\-observation" in result.output
    assert "| ui_source_revision | unknown |" in result.output
    assert "[click](javascript:bad)" not in result.output
    assert "<script>" not in result.output
    assert "\x1b" not in result.output
    assert "\n- [click]" not in result.output
    assert "Execution: NOT AUTHORIZED" in result.output
    assert (
        "Stock V2.57 boot, stock IPC and device acceptance: NOT RUN / UNVERIFIED" in result.output
    )
    data = json.loads(invoke(path, "show", "--id", "record", "--format", "json").output)
    assert data["limitations"] == [unsafe]
    assert data["identity"] == candidate.model_dump(mode="json")["identity"]


def test_local_regular_paths_only(tmp_path):
    assert invoke(tmp_path).exit_code == 2
    assert invoke(tmp_path / "missing").exit_code == 2
    for path in (
        r"\\server\share\registry.json",
        "//server/share/registry.json",
        "NUL",
        "a:stream",
        "C:registry.json",
    ):
        assert invoke(path).exit_code == 2
    target = write_registry(tmp_path)
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("host does not permit symlinks")
    assert invoke(link).exit_code == 2
    directory_link = tmp_path / "linked"
    directory_link.symlink_to(tmp_path, target_is_directory=True)
    assert invoke(directory_link / target.name).exit_code == 2


@pytest.mark.skipif(os.name == "nt", reason="FIFO is a POSIX special file")
def test_fifo_is_refused_before_open(tmp_path):
    path = tmp_path / "fifo"
    if os.name != "nt":
        os.mkfifo(path)
    assert invoke(path).exit_code == 2


def test_generated_registry_size_and_model_bypasses():
    candidate = record().model_copy(update={"limitations": ("\u00e9" * MAX_REGISTRY_BYTES,)})
    with pytest.raises(RegistryError, match="1 MiB"):
        build_registry([candidate])
    bypass = CompatibilityRegistry.model_construct(
        schema_version="lab-compatibility-registry/v1", records=(candidate,)
    )
    with pytest.raises(RegistryError, match="1 MiB"):
        registry_json(bypass)
    forged = record().model_copy(update={"execution_authority": True})
    bypass = bypass.model_copy(update={"records": (forged,)})
    with pytest.raises(RegistryError):
        registry_json(bypass)


def test_pretty_output_limit_includes_formatting_and_final_newline():
    base = record()
    empty = registry_json(build_registry([base.model_copy(update={"limitations": ("x",)})]))
    count = MAX_REGISTRY_BYTES - len(empty.encode("utf-8")) + 1
    candidate = base.model_copy(update={"limitations": ("x" * count,)})
    registry = build_registry([candidate])
    output = registry_json(registry)
    assert len(output.encode("utf-8")) == MAX_REGISTRY_BYTES
    assert parse_registry_json(output) == registry
    with pytest.raises(RegistryError, match="1 MiB"):
        build_registry([base.model_copy(update={"limitations": ("x" * (count + 1),)})])


def test_nested_json_api_has_deterministic_refusal():
    with pytest.raises(RegistryError):
        parse_registry_json("[" * 2000)


def test_unicode_show_uses_bounded_utf8_encoding(tmp_path):
    candidate = record("unicode").model_copy(update={"limitations": ("\u00e9" * 200_000,)})
    path = write_registry(tmp_path, [candidate])
    result = invoke(path, "show", "--id", "unicode", "--format", "json")
    assert result.exit_code == 0, result.output[:200]
    assert len(result.output.encode("utf-8")) < MAX_REGISTRY_BYTES
    assert json.loads(result.output) == candidate.model_dump(mode="json")


def test_multiple_generated_records_cannot_exceed_canonical_limit():
    candidates = [
        record(str(index), scenario_id=str(index)).model_copy(
            update={"limitations": ("x" * 100_000,)}
        )
        for index in range(11)
    ]
    with pytest.raises(RegistryError, match="1 MiB"):
        build_registry(candidates)
