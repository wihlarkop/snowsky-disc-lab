from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from jsonschema import validate

from snowsky_disc_lab.contracts import (
    FirmwareManifest,
    ManifestKind,
    UIManifest,
    load_manifest,
    schema_documents,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
INVALID_EXAMPLES = EXAMPLES / "invalid"
SCHEMAS = ROOT / "schemas"


def test_loads_valid_ui_manifest_and_allows_output_not_to_exist() -> None:
    manifest = load_manifest(EXAMPLES / "ui-valid.yaml", "ui")

    assert isinstance(manifest, UIManifest)
    assert manifest.api_version == "lab-ui/v1"
    assert manifest.metadata.name == "example-fork"
    assert manifest.source.revision == "0123456789abcdef0123456789abcdef01234567"
    assert manifest.build.preset == "diskos-musl"
    assert manifest.build.output == "ui/mq_ui"
    assert manifest.runtime.display == [360, 360]
    assert manifest.claims.firmware == ["2.57"]


def test_loads_valid_firmware_manifest() -> None:
    manifest = load_manifest(EXAMPLES / "firmware-valid.yaml", "firmware")

    assert isinstance(manifest, FirmwareManifest)
    assert manifest.kind == "Firmware"
    assert manifest.device == "snowsky-disc"
    assert manifest.firmware.main == "2.57"
    assert manifest.firmware.rootfs_sha256 == "a" * 64
    assert manifest.runtime is not None
    assert manifest.runtime.runner_id == "qemu-disc-v257"


def test_firmware_runtime_runner_and_hashes_are_optional(tmp_path: Path) -> None:
    manifest_path = tmp_path / "firmware.yaml"
    manifest_path.write_text(
        "apiVersion: lab-firmware/v1\n"
        "kind: Firmware\n"
        "device: snowsky-disc\n"
        "firmware:\n  main: '2.57'\n  recovery: '18'\n",
        encoding="utf-8",
    )

    manifest = load_manifest(manifest_path, "firmware")

    assert isinstance(manifest, FirmwareManifest)
    assert manifest.runtime is None
    assert manifest.firmware.rootfs_sha256 is None
    assert manifest.firmware.player_sha256 is None


@pytest.mark.parametrize(
    "example",
    [
        "ui-invalid-extra.yaml",
        "ui-invalid-revision.yaml",
        "ui-invalid-output.yaml",
        "ui-invalid-version.yaml",
        "ui-invalid-missing.yaml",
        "firmware-invalid-extra.yaml",
        "firmware-invalid-hash.yaml",
        "firmware-invalid-device.yaml",
        "ui-invalid-duplicate.yaml",
    ],
)
def test_rejects_invalid_contract_examples(example: str) -> None:
    kind: ManifestKind = "firmware" if example.startswith("firmware") else "ui"

    with pytest.raises(ValueError):
        load_manifest(INVALID_EXAMPLES / example, kind)


def test_normalizes_ui_name_after_safe_slug_validation(tmp_path: Path) -> None:
    source = (EXAMPLES / "ui-valid.yaml").read_text(encoding="utf-8")
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(
        source.replace("name: example-fork", "name: Example-Fork"), encoding="utf-8"
    )

    manifest = load_manifest(manifest_path, "ui")

    assert isinstance(manifest, UIManifest)
    assert manifest.metadata.name == "example-fork"

    import yaml

    validate(
        instance=yaml.safe_load(manifest_path.read_text(encoding="utf-8")),
        schema=schema_documents()["lab-ui-v1.schema.json"],
    )


@pytest.mark.parametrize("name", [" example-fork", "\u212a"])
def test_rejects_unsafe_ui_name(tmp_path: Path, name: str) -> None:
    source = (EXAMPLES / "ui-valid.yaml").read_text(encoding="utf-8")
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(
        source.replace("name: example-fork", f"name: {json.dumps(name)}"), encoding="utf-8"
    )

    with pytest.raises(ValueError):
        load_manifest(manifest_path, "ui")


@pytest.mark.parametrize(
    "output",
    [
        "../outside/mq_ui",
        "/absolute/mq_ui",
        "C:/build/mq_ui",
        "\\\\server\\share\\mq_ui",
        "ui/../mq_ui",
        "ui//mq_ui",
    ],
)
def test_rejects_unsafe_output_syntax(tmp_path: Path, output: str) -> None:
    source = (EXAMPLES / "ui-valid.yaml").read_text(encoding="utf-8")
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(
        source.replace("output: ui/mq_ui", f"output: {json.dumps(output)}"),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_manifest(manifest_path, "ui")


@pytest.mark.parametrize(
    "replacement",
    [
        ("target: snowsky-disc", "target: another-device"),
        ("architecture: mipsel", "architecture: mips"),
        ("ipc: fiio-posix-mqueue", "ipc: shell"),
        ("display: [360, 360]", "display: [true, 360]"),
        ("display: [360, 360]", "display: [360, 360, 360]"),
    ],
)
def test_rejects_incompatible_ui_runtime_values(
    tmp_path: Path, replacement: tuple[str, str]
) -> None:
    source = (EXAMPLES / "ui-valid.yaml").read_text(encoding="utf-8")
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(source.replace(*replacement), encoding="utf-8")

    with pytest.raises(ValueError):
        load_manifest(manifest_path, "ui")


def test_rejects_yaml_syntax_without_echoing_untrusted_content(tmp_path: Path) -> None:
    marker = "untrusted-value-should-not-appear"
    manifest_path = tmp_path / "bad.yaml"
    manifest_path.write_text(f"apiVersion: {marker}\n: invalid\n", encoding="utf-8")

    with pytest.raises(ValueError) as error:
        load_manifest(manifest_path, "ui")

    assert marker not in str(error.value)


def test_rejects_schema_error_without_echoing_untrusted_content(tmp_path: Path) -> None:
    marker = "secret-revision-value"
    manifest_path = tmp_path / "bad.yaml"
    manifest_path.write_text(
        "apiVersion: lab-ui/v1\n"
        "kind: UI\n"
        "metadata:\n  name: test\n"
        f"source:\n  revision: {marker}\n"
        "build:\n  preset: synthetic\n  output: ui/mq_ui\n"
        "runtime:\n  target: snowsky-disc\n  architecture: mipsel\n"
        "  display: [360, 360]\n  ipc: fiio-posix-mqueue\n"
        "claims:\n  firmware: []\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as error:
        load_manifest(manifest_path, "ui")

    assert marker not in str(error.value)


def test_rejects_manifest_larger_than_input_limit(tmp_path: Path) -> None:
    manifest_path = tmp_path / "large.yaml"
    manifest_path.write_bytes(b"#" + b"x" * (64 * 1024))

    with pytest.raises(ValueError, match="size limit"):
        load_manifest(manifest_path, "ui")


def test_rejects_non_utf8_input(tmp_path: Path) -> None:
    manifest_path = tmp_path / "binary.yaml"
    manifest_path.write_bytes(b"apiVersion: \xff")

    with pytest.raises(ValueError, match="UTF-8"):
        load_manifest(manifest_path, "ui")


def test_safe_loader_rejects_python_object_tags(tmp_path: Path) -> None:
    manifest_path = tmp_path / "tagged.yaml"
    manifest_path.write_text("!!python/object/apply:os.system ['echo unsafe']", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid YAML syntax"):
        load_manifest(manifest_path, "ui")


def test_rejects_yaml_anchors_and_aliases(tmp_path: Path) -> None:
    manifest_path = tmp_path / "aliases.yaml"
    manifest_path.write_text(
        "apiVersion: &version lab-ui/v1\nkind: UI\nmetadata:\n  name: *version\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="anchors and aliases"):
        load_manifest(manifest_path, "ui")


def test_rejects_yaml_nesting_past_limit(tmp_path: Path) -> None:
    manifest_path = tmp_path / "deep.yaml"
    nesting = 65
    manifest_path.write_text(
        "apiVersion: " + "[" * nesting + "x" + "]" * nesting,
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="nesting exceeds"):
        load_manifest(manifest_path, "ui")


def test_preserves_os_error_for_missing_manifest(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        load_manifest(tmp_path / "missing.yaml", "ui")


def test_rejects_directory_as_manifest_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="regular file"):
        load_manifest(tmp_path, "ui")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="this platform does not support POSIX FIFOs")
def test_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    fifo_path = tmp_path / "manifest.fifo"
    mkfifo = getattr(os, "mkfifo", None)
    if mkfifo is None:
        pytest.skip("this platform does not support POSIX FIFOs")
    mkfifo(fifo_path)

    with pytest.raises(ValueError, match="regular file"):
        load_manifest(fifo_path, "ui")


def test_rejects_output_that_resolves_through_symlink_outside_manifest_directory(
    tmp_path: Path,
) -> None:
    manifest_dir = tmp_path / "manifest"
    outside_dir = tmp_path / "outside"
    manifest_dir.mkdir()
    outside_dir.mkdir()
    link = manifest_dir / "ui"
    try:
        link.symlink_to(outside_dir, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"directory symlinks are unavailable: {type(error).__name__}")

    manifest_path = manifest_dir / "manifest.yaml"
    manifest_path.write_text(
        "apiVersion: lab-ui/v1\n"
        "kind: UI\n"
        "metadata:\n  name: test\n"
        "source:\n  revision: 0123456789abcdef0123456789abcdef01234567\n"
        "build:\n  preset: synthetic\n  output: ui/mq_ui\n"
        "runtime:\n  target: snowsky-disc\n  architecture: mipsel\n"
        "  display: [360, 360]\n  ipc: fiio-posix-mqueue\n"
        "claims:\n  firmware: []\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="output path"):
        load_manifest(manifest_path, "ui")


def test_rejects_wrong_firmware_device(tmp_path: Path) -> None:
    source = (EXAMPLES / "firmware-valid.yaml").read_text(encoding="utf-8")
    manifest_path = tmp_path / "firmware.yaml"
    manifest_path.write_text(
        source.replace("device: snowsky-disc", "device: snowsky-echo"), encoding="utf-8"
    )

    with pytest.raises(ValueError):
        load_manifest(manifest_path, "firmware")


@pytest.mark.parametrize(
    ("example", "schema_name"),
    [
        ("ui-valid.yaml", "lab-ui-v1.schema.json"),
        ("firmware-valid.yaml", "lab-firmware-v1.schema.json"),
    ],
)
def test_valid_examples_match_exported_json_schemas(example: str, schema_name: str) -> None:
    import yaml

    with (EXAMPLES / example).open(encoding="utf-8") as stream:
        instance = yaml.safe_load(stream)

    validate(instance=instance, schema=schema_documents()[schema_name])


def test_checked_in_schema_documents_match_models() -> None:
    assert set(schema_documents()) == {
        "lab-ui-v1.schema.json",
        "lab-firmware-v1.schema.json",
    }
    for filename, schema in schema_documents().items():
        checked_in = json.loads((SCHEMAS / filename).read_text(encoding="utf-8"))
        assert checked_in == schema


def test_json_schemas_forbid_unknown_properties() -> None:
    documents = schema_documents()

    assert documents["lab-ui-v1.schema.json"]["additionalProperties"] is False
    assert documents["lab-firmware-v1.schema.json"]["additionalProperties"] is False
