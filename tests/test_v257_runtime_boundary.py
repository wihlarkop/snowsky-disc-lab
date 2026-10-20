"""Review contract against the existing inspect validator; no Docker or QEMU calls."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from snowsky_disc_lab import synthetic_runtime as runtime
from snowsky_disc_lab.source_lock import load_source_lock
from snowsky_disc_lab.sources import source_path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT: dict[str, Any] = json.loads(
    (ROOT / "docs/v257-runtime-boundary-contract.json").read_text(encoding="utf-8")
)


@pytest.fixture
def inspection(tmp_path) -> tuple[dict[str, Any], Path, Path, str, list[str]]:
    """Symbolic bind roles resolve only to pytest-owned, unmounted paths."""
    inputs, rootfs = tmp_path / "inputs", tmp_path / "synthetic-input"
    token = "review-only-owner"
    args = runtime.container_args(inputs, rootfs, token, "filesystem")
    sources = {"verified-execution-inputs": inputs, "owned-synthetic-input": rootfs}
    item: dict[str, Any] = {
        "Config": {
            "Image": runtime.BASE_IMAGE,
            "User": CONTRACT["allowed"]["user"],
            "Labels": {runtime.LABEL: token},
            "Cmd": args[-5:],
            "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        },
        "HostConfig": copy.deepcopy(CONTRACT["allowed"]["host_config"]),
        "Mounts": [
            {
                "Type": "bind",
                "Source": str(sources[binding["source_role"]]),
                "Destination": binding["target"],
                "RW": not binding["read_only"],
            }
            for binding in CONTRACT["allowed"]["binds"]
        ],
    }
    return item, inputs, rootfs, token, args


def test_review_contract_stays_bound_to_locked_source_and_current_profile(inspection, tmp_path):
    lock = load_source_lock(ROOT / "upstreams.lock.yaml")
    source = next(entry for entry in lock.sources if entry.id == "snowsky-disc-qemu")
    assert CONTRACT["upstream_commit"] == source.commit
    assert source_path(tmp_path / "cache", source).name == (
        f"{source.commit}-{CONTRACT['source_projection']}"
    )
    assert CONTRACT["stock_v257_boot"] == "NOT RUN"
    validated = runtime.validate_container(*inspection)
    assert validated["uid_gid"] == CONTRACT["allowed"]["user"]
    assert validated["private_writable_tmpfs"] == CONTRACT["allowed"]["host_config"]["Tmpfs"]
    assert {
        **validated["verified_host_config"],
        "SecurityOpt": ["no-new-privileges:true"],
    } == CONTRACT["allowed"]["host_config"]


@pytest.mark.parametrize("target", CONTRACT["refused"]["extra_bind_targets"])
def test_stock_and_host_bind_requests_are_refused(inspection, target):
    item, inputs, *_ = inspection
    item["Mounts"].append(
        {"Type": "bind", "Source": str(inputs), "Destination": target, "RW": True}
    )
    with pytest.raises(runtime.RuntimeRefused):
        runtime.validate_container(*inspection)


@pytest.mark.parametrize("mount_request", CONTRACT["refused"]["extra_filesystems"])
def test_extra_filesystem_requests_are_refused(inspection, mount_request):
    item = inspection[0]
    item["Mounts"].append(
        {"Type": mount_request["type"], "Destination": mount_request["target"], "RW": True}
    )
    with pytest.raises(runtime.RuntimeRefused):
        runtime.validate_container(*inspection)


@pytest.mark.parametrize("target", CONTRACT["refused"]["extra_tmpfs_targets"])
def test_stock_tmpfs_aliases_are_not_silently_supported(inspection, target):
    item = inspection[0]
    item["HostConfig"]["Tmpfs"][target] = next(iter(runtime.TMPFS.values()))
    with pytest.raises(runtime.RuntimeRefused):
        runtime.validate_container(*inspection)


@pytest.mark.parametrize("capability", CONTRACT["refused"]["capability_additions"])
def test_added_capability_requests_are_refused(inspection, capability):
    inspection[0]["HostConfig"]["CapAdd"] = [capability]
    with pytest.raises(runtime.RuntimeRefused):
        runtime.validate_container(*inspection)


@pytest.mark.parametrize("device", CONTRACT["refused"]["device_paths"])
def test_host_device_requests_are_refused(inspection, device):
    inspection[0]["HostConfig"]["Devices"] = [
        {"PathOnHost": device, "PathInContainer": device, "CgroupPermissions": "rwm"}
    ]
    with pytest.raises(runtime.RuntimeRefused):
        runtime.validate_container(*inspection)


@pytest.mark.parametrize("setting", CONTRACT["refused"]["host_config_changes"])
def test_namespace_and_security_changes_are_refused(inspection, setting):
    inspection[0]["HostConfig"][setting["field"]] = setting["value"]
    with pytest.raises(runtime.RuntimeRefused):
        runtime.validate_container(*inspection)


@pytest.mark.parametrize("target", ["/inputs", "/synthetic-rootfs"])
def test_existing_inputs_cannot_be_made_writable(inspection, target):
    mount = next(entry for entry in inspection[0]["Mounts"] if entry["Destination"] == target)
    mount["RW"] = True
    with pytest.raises(runtime.RuntimeRefused):
        runtime.validate_container(*inspection)
