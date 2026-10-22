"""Byte/receipt refusals and owned Docker policy, separate from real hosted QEMU."""

from __future__ import annotations

import copy
import hashlib
import subprocess
from pathlib import Path

import pytest
from test_qemu_runtime_build import qemu_runtime_build as build
from test_synthetic_runtime import Docker
from test_synthetic_runtime import inputs as runtime_inputs

from snowsky_disc_lab import synthetic_runtime as runtime
from snowsky_disc_lab import synthetic_ui as ui

inputs = runtime_inputs


class UIDocker(Docker):
    damage = False

    def __call__(self, args, **kwargs):
        if args[1] == "start" and self.mode in ui.CASES:
            token = self.inspection[0]["Config"]["Labels"][runtime.LABEL]
            output = ui.sample_output(self.mode, token)
            if self.damage:
                output = output.replace("f0c020ff", "00000000", 1)
            return subprocess.CompletedProcess(args, 0, output)
        return super().__call__(args, **kwargs)


def stage_ui(inputs):
    directory, evidence = inputs
    (directory / ui.GUEST_ELF).write_bytes(ui.GUEST_ELF.encode())
    (directory / ui.GUEST_ELF).chmod(0o555)
    evidence["synthetic_ui_guest"] = {
        "source": {"sha256": ui.GUEST_SOURCE_SHA256},
        "elf": {"sha256": hashlib.sha256(ui.GUEST_ELF.encode()).hexdigest()},
    }
    return directory, evidence


def test_journey_validates_pixels_input_rejections_distinct_sessions_and_cleanup(
    inputs, tmp_path, monkeypatch
):
    directory, evidence = stage_ui(inputs)
    docker = UIDocker()
    monkeypatch.setattr(runtime, "_docker", docker)
    receipt = ui.acceptance(directory, evidence, tmp_path / "store")
    ui.validate_receipt(receipt)
    assert len({s["observation"]["session_identity"] for s in receipt["sessions"]}) == 6
    assert len([c for c in docker.calls if c[1] == "rm"]) == 6
    frames = receipt["sessions"][0]["observation"]["frames"]
    assert frames["initial"]["sha256"] == ui.FRAME_HASHES["initial"]
    assert frames["changed"]["sha256"] == ui.FRAME_HASHES["changed"]
    assert frames["initial"]["sha256"] != frames["changed"]["sha256"]
    assert [s["observation"]["guest_exit_code"] for s in receipt["sessions"]] == [
        0,
        0,
        41,
        42,
        43,
        45,
    ]
    # Missing, contradictory, malformed, boolean-as-integer and unsafe evidence.
    mutations = [
        lambda r: r.pop("input"),
        lambda r: r.update(guest_elf_sha256=""),
        lambda r: r.update(qemu_sha256="0" * 64),
        lambda r: r["geometry"].update(width=True),
        lambda r: r["sessions"][0]["observation"]["frames"]["changed"].update(sha256="0" * 64),
        lambda r: r["sessions"][0]["cleanup"].update(container_removed=False),
        lambda r: r["sessions"][0]["isolation"].update(host_devices=True),
        lambda r: r["sessions"][0]["isolation"]["verified_host_config"].update(Privileged=0),
        lambda r: r["sessions"][1].update(observation=r["sessions"][0]["observation"]),
        lambda r: r["sessions"][0]["isolation"].update(stdout_limit_bytes=1024),
        lambda r: r["sessions"][0]["isolation"].update(stdout_limit_bytes=3072.0),
        lambda r: r["sessions"][0]["isolation"].update(mounts=[]),
        lambda r: r["sessions"][0]["isolation"]["mounts"][0].update(read_only=False),
        lambda r: r.update(authenticated=True),
    ]
    for mutate in mutations:
        invalid = copy.deepcopy(receipt)
        mutate(invalid)
        with pytest.raises(ValueError):
            ui.validate_receipt(invalid)


@pytest.mark.parametrize(
    "damage", ["pixel", "size", "session", "duplicate", "missing", "exit", "order"]
)
def test_transcript_is_bound_to_observed_bytes_fresh_session_and_exact_grammar(damage):
    token = "a" * 32
    text = ui.sample_output("ui-normal", token)
    if damage == "pixel":
        text = text.replace("f0c020ff", "00000000", 1)
    elif damage == "size":
        text = text.replace("UI_CHANGED=", "UI_CHANGED=00")
    elif damage == "session":
        text = text.replace(token, "b" * 32)
    elif damage == "duplicate":
        text += "UI_EVENT=cursor:2->3\n"
    elif damage == "exit":
        text = text.replace("UI_EXIT=0", "UI_EXIT=43")
    elif damage == "order":
        text = text.replace("UI_EXIT=0\n", "") + "UI_EXIT=0\n"
    else:
        text = "UI_EVENT=cursor:2->3\n"
    with pytest.raises(ValueError):
        ui.parse_execution_output(text, "ui-normal", token)


@pytest.mark.parametrize("failure", ["damage", "cleanup_failure", "foreign_owner", "timeout"])
def test_bad_frame_failed_cleanup_foreign_owner_and_deadline_quarantine_owned_session(
    inputs, tmp_path, monkeypatch, failure
):
    directory, evidence = stage_ui(inputs)
    docker = UIDocker()
    if failure == "timeout":

        def call(args, **kwargs):
            if args[1] == "start":
                raise subprocess.TimeoutExpired(args, 15)
            return docker(args, **kwargs)

        monkeypatch.setattr(runtime, "_docker", call)
    else:
        setattr(docker, failure, True)
        monkeypatch.setattr(runtime, "_docker", docker)
    with pytest.raises(runtime.RuntimeRefused) as caught:
        runtime.launch(directory, evidence, tmp_path / "store", _case="ui-normal")
    assert caught.value.receipt is not None
    assert caught.value.receipt["status"] == "quarantined"
    removals = [c for c in docker.calls if c[1] == "rm"]
    assert len(removals) == (0 if failure == "foreign_owner" else 1)


def test_source_and_build_recipe_are_bound_to_same_reviewed_mips_guest():
    root = Path(__file__).resolve().parents[1]
    assert (
        hashlib.sha256((root / ui.GUEST_SOURCE).read_bytes()).hexdigest() == ui.GUEST_SOURCE_SHA256
    )
    assert build.UI_GUEST_SOURCE_SHA256 == ui.GUEST_SOURCE_SHA256
    assert build.UI_GUEST_ELF == ui.GUEST_ELF
    reference = build.read_reference()
    command = build.build_container_command(
        reference,
        include_smoke_guest=True,
        include_mqueue_guest=True,
        include_ipc_handoff_guest=True,
        include_ipc_supervision_guest=True,
        include_ui_guest=True,
    )
    assert "-static -march=mips32 -mabi=32 -EL" in command
    assert f"/build/smoke/{ui.GUEST_ELF}" in command
    assert "measure-ui-guest" in command
    assert ui.GUEST_SOURCE.split("/")[-1] in command
    assert "__UI_GUEST_STEPS__" not in command
    with pytest.raises(build.StopBuild):
        build.build_container_command(reference, include_ui_guest=True)


def test_ui_guest_missing_or_source_mismatch_refuses_before_container_start(inputs, tmp_path):
    directory, evidence = inputs
    with pytest.raises(runtime.RuntimeRefused):
        runtime.launch(directory, evidence, tmp_path / "store", _case="ui-normal")
    directory, evidence = stage_ui(inputs)
    evidence["synthetic_ui_guest"]["source"]["sha256"] = "0" * 64
    with pytest.raises(runtime.RuntimeRefused):
        runtime.launch(directory, evidence, tmp_path / "store", _case="ui-normal")


@pytest.mark.parametrize(
    "data",
    [b'{"status":"passed","status":"failed"}', b"{}", b"null", b"[", b"x" * (128 * 1024 + 1)],
    ids=["duplicate", "missing", "null", "malformed", "oversized"],
)
def test_portable_receipt_rejects_duplicate_malformed_missing_and_oversized_data(data):
    with pytest.raises(ValueError):
        ui.parse_receipt(data)
