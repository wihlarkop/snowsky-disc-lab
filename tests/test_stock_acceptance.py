"""Firmware-free executable comparator integration; no stock observation is made."""

from __future__ import annotations

import copy
import io
import json
import struct
import wave
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from snowsky_disc_lab.stock_acceptance import (
    INPUTS,
    Context,
    Expected,
    InputObservation,
    InputPlan,
    LifecycleObservation,
    MediaObservation,
    StockReport,
    compare_inputs,
    compare_lifecycle,
    compare_media,
    input_payload,
    parse_report,
    preparation_report,
    scenario_digest,
)
from snowsky_disc_lab.stock_fixtures import (
    FORMAT,
    FRAME_COUNT,
    PCMFormat,
    compare_pcm,
    media_identity,
    pcm_fixture,
    sha256,
    wav_fixture,
)

ROOT = Path(__file__).resolve().parents[1]


def frame(data: bytes) -> dict[str, Any]:
    return {
        "width": 360,
        "height": 360,
        "stride_bytes": 1440,
        "pixel_format": "RGBA8888",
        "bytes": 518400,
        "sha256": sha256(data),
    }


def journey() -> tuple[dict[str, Any], list[bytes]]:
    """Fabricated contract values, explicitly simulated, never stock capture evidence."""
    report = preparation_report("a" * 32).model_dump()
    context = report["context"]
    for name in context["identities"]:
        if name != "firmware_version":
            context["identities"][name] = {
                "sha256": sha256(name.encode()),
                "provenance": "declared-unverified",
            }
    frames = [bytes((index + 1, 50, 70, 255)) * (360 * 360) for index in range(4)]
    plan = {
        "steps": [
            {
                "step_id": item[0],
                "sequence": index + 1,
                "payload_sha256": sha256(input_payload(index)),
                "response": item[2],
                "deadline_ms": 1000,
                "frame": frame(frames[index]),
            }
            for index, item in enumerate(INPUTS)
        ]
    }
    inputs = [
        {
            **step,
            "context": copy.deepcopy(context),
            "session_id": "1" * 32,
            "sent_ms": 100 + index * 300,
            "observed_ms": 350 + index * 300,
            "generation": index + 1,
        }
        for index, step in enumerate(plan["steps"])
    ]
    for item in inputs:
        del item["deadline_ms"]
    ownership: list[dict[str, Any]] = [
        {
            "session_id": str(index + 1) * 32,
            "processes": [
                {
                    "role": role,
                    "pid": 100 + index * 2 + role_index,
                    "start_identity": str(index * 2 + role_index + 4) * 32,
                }
                for role_index, role in enumerate(("mq_ui", "mq_player"))
            ],
        }
        for index in range(3)
    ]
    expected_lifecycle = {
        "ownership": ownership,
        "readiness_frame": frame(frames[0]),
        "readiness_player_ack_sha256": sha256(b"first-party-ack"),
        "boot_deadline_ms": 1000,
        "stop_deadline_ms": 500,
        "restart_deadline_ms": 1500,
        "initial_state_sha256": sha256(b"empty-state"),
        "persistent_state_sha256": sha256(b"generated-state"),
    }
    sessions = []
    for index, mode in enumerate(("cold-clean", "restart-persistent", "restart-clean")):
        owner = ownership[index]
        sid = owner["session_id"]
        sessions.append(
            {
                "context": copy.deepcopy(context),
                "session_id": sid,
                "mode": mode,
                "previous_session_id": str(index) * 32 if index else None,
                "started_ms": index * 2000,
                "player_ready_ms": index * 2000 + 10,
                "ui_ready_ms": index * 2000 + 20,
                "stop_requested_ms": index * 2000 + 1800,
                "stopped_ms": index * 2000 + 1900,
                "readiness_session_id": sid,
                "readiness_frame": frame(frames[0]),
                "readiness_player_ack_sha256": expected_lifecycle["readiness_player_ack_sha256"],
                "initial_state_sha256": expected_lifecycle[
                    "persistent_state_sha256" if index == 1 else "initial_state_sha256"
                ],
                "final_state_sha256": expected_lifecycle["persistent_state_sha256"],
                "processes": [
                    {
                        **process,
                        "session_id": sid,
                        "owner_run_id": context["run_id"],
                        "exit_code": 0,
                        "reaped": True,
                    }
                    for process in owner["processes"]
                ],
                "ownership_checked": True,
                "ipc_removed": True,
                "volatile_state_removed": True,
                "resources_released": True,
            }
        )
    report["expected"] = {
        "media": media_identity().model_dump(),
        "media_deadline_ms": 5000,
        "inputs": plan,
        "lifecycle": expected_lifecycle,
    }
    report["scenario_sha256"] = scenario_digest(Expected.model_validate(report["expected"]))
    report["observed"] = {
        "context": copy.deepcopy(context),
        "input_session_id": "1" * 32,
        "inputs": inputs,
        "media": {
            "context": copy.deepcopy(context),
            "session_id": "1" * 32,
            "imported_ms": 30,
            "indexed_ms": 40,
            "capture_started_ms": 1000,
            "capture_ended_ms": 1600,
            "imported_wav_sha256": media_identity().wav_sha256,
            "indexed_media_sha256": [media_identity().wav_sha256],
            "pcm": compare_pcm(pcm_fixture(), FORMAT, media_identity()).model_dump(),
        },
        "lifecycle": {"sessions": sessions},
        "basis": "simulated-contract-test",
    }
    report["status"] = "UNVERIFIED"
    return report, frames


def parse(data: dict[str, Any]) -> StockReport:
    return parse_report(json.dumps(data).encode())


def change(data: dict[str, Any], path: str, value: object) -> None:
    current: Any = data
    parts = path.split(".")
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    final = int(parts[-1]) if isinstance(current, list) else parts[-1]
    current[final] = value


def test_first_party_wave_and_pcm_are_canonical_complete_non_silent_stereo() -> None:
    identity = media_identity()
    assert identity.frame_count == FRAME_COUNT == 24000
    assert identity.sample_count == 48000
    assert identity.pcm_bytes == 96000
    assert identity.pcm_sha256 == "cc38b3a20386adda4cb1369b67d4b70a64d2fa74dffc2ba263851dd9b3a9f0fe"
    assert identity.wav_sha256 == "e3b36f08b99a78c49daee36aabf58408368a09efae53552659f67f670310b192"
    assert wav_fixture() == wav_fixture()
    with wave.open(io.BytesIO(wav_fixture())) as stream:
        assert (stream.getnchannels(), stream.getsampwidth(), stream.getframerate()) == (
            2,
            2,
            48000,
        )
        assert stream.getnframes() == FRAME_COUNT
        assert stream.getcomptype() == "NONE"
        assert stream.readframes(FRAME_COUNT + 1) == pcm_fixture()
        assert stream.readframes(1) == b""
    samples = list(struct.iter_unpack("<hh", pcm_fixture()))
    assert any(left != right for left, right in samples)
    assert all(any(sample[channel] for sample in samples) for channel in range(2))
    assert compare_pcm(pcm_fixture(), FORMAT, identity).pcm_sha256 == identity.pcm_sha256


@pytest.mark.parametrize(
    "kind", ["silent", "one-silent-channel", "truncated", "extra", "samples", "partial"]
)
def test_pcm_refuses_bad_complete_track(kind: str) -> None:
    data = pcm_fixture()
    bad = {
        "silent": bytes(len(data)),
        "one-silent-channel": b"".join(
            struct.pack("<hh", left, 0) for left, _ in struct.iter_unpack("<hh", data)
        ),
        "truncated": data[:-4],
        "extra": data + b"\0\0\0\0",
        "samples": bytes((data[0] ^ 1,)) + data[1:],
        "partial": data[:48000] + bytes(48000),
    }[kind]
    with pytest.raises(ValueError):
        compare_pcm(bad, FORMAT, media_identity())


@pytest.mark.parametrize("field,value", [("channels", 1), ("sample_rate", 44100)])
def test_pcm_refuses_format(field: str, value: int) -> None:
    data = FORMAT.model_dump()
    data[field] = value
    with pytest.raises(ValueError, match="format"):
        compare_pcm(pcm_fixture(), PCMFormat.model_validate(data), media_identity())


def test_pcm_refuses_mismatched_selected_media_and_revalidates_instances() -> None:
    bad = media_identity().model_copy(update={"pcm_sha256": "0" * 64})
    with pytest.raises(ValueError, match="identity"):
        compare_pcm(pcm_fixture(), FORMAT, bad)
    bad_format = FORMAT.model_copy(update={"sample_width_bytes": True})
    with pytest.raises(ValueError):
        compare_pcm(pcm_fixture(), bad_format, media_identity())


def test_complete_simulated_journey_compares_bytes_but_never_promotes_stock() -> None:
    data, frames = journey()
    report = parse(data)
    assert report.observed is not None
    assert report.expected.inputs is not None
    assert report.expected.lifecycle is not None
    assert compare_inputs(
        report.context, "1" * 32, report.expected.inputs, report.observed.inputs, frames
    )
    assert compare_lifecycle(report.context, report.expected.lifecycle, report.observed.lifecycle)
    assert compare_media(
        report.context,
        report.expected,
        report.observed.media,
        report.observed.lifecycle.sessions[0],
        pcm_fixture(),
    )
    assert report.status == "UNVERIFIED"
    assert report.stock_execution == "NOT RUN"
    assert report.support_status == "unknown"
    assert report.verified is report.authenticated is report.launch_authorized is False


@pytest.mark.parametrize(
    "kind",
    [
        "missing",
        "wrong-bytes",
        "wrong-frame",
        "short-frame",
        "stale",
        "late",
        "order",
        "generation",
    ],
)
def test_input_comparator_rejects_missing_wrong_stale_and_late_frames(kind: str) -> None:
    data, frames = journey()
    plan = InputPlan.model_validate(data["expected"]["inputs"])
    observations = data["observed"]["inputs"]
    if kind == "missing":
        observations.pop()
    elif kind == "wrong-bytes":
        frames[0] = bytes(len(frames[0]))
    elif kind == "wrong-frame":
        observations[0]["frame"]["sha256"] = "0" * 64
    elif kind == "short-frame":
        frames[0] = frames[0][:-4]
    elif kind == "stale":
        observations[0]["session_id"] = "f" * 32
    elif kind == "late":
        observations[-1]["observed_ms"] += 1001
    elif kind == "order":
        observations.reverse()
    elif kind == "generation":
        observations[1]["generation"] = 1
    with pytest.raises(ValueError):
        compare_inputs(
            Context.model_validate(data["context"]),
            "1" * 32,
            plan,
            [InputObservation.model_validate(item) for item in observations],
            frames,
        )


@pytest.mark.parametrize(
    "path,value",
    [
        ("status", "PASS"),
        ("stock_execution", "PASS"),
        ("verified", True),
        ("verified", 0),
        ("authenticated", 0),
        ("launch_authorized", 0),
        ("support_status", "verified-emulator"),
        ("vendor_authenticity", "verified"),
        ("scenario_sha256", "0" * 64),
        ("expected.media.pcm_sha256", "0" * 64),
        ("observed.inputs.0.context.identities.package.sha256", "0" * 64),
        ("observed.context.identities.runner_binary.sha256", "0" * 64),
        ("context.identities.package", {"sha256": None, "provenance": "unmeasured"}),
        ("observed.inputs.0.frame.width", 360.0),
        ("observed.inputs.0.frame.width", True),
        ("observed.inputs.0.sequence", True),
        ("observed.inputs.0.sent_ms", 19),
        ("observed.inputs.3.observed_ms", 1801),
        ("observed.media.session_id", "f" * 32),
        ("observed.media.context.identities.runner_binary.sha256", "0" * 64),
        ("observed.media.imported_wav_sha256", "0" * 64),
        ("observed.media.indexed_media_sha256", ["0" * 64]),
        ("observed.media.capture_started_ms", 19),
        ("observed.media.capture_ended_ms", 1801),
        ("observed.media.pcm.pcm_sha256", "0" * 64),
        ("observed.media.pcm.frame_count", 23999),
        ("observed.media.pcm.sample_count", 24000),
        ("observed.media.pcm.pcm_bytes", 95996),
        ("observed.media.pcm.captured_format.channels", 1),
        ("observed.media.pcm.all_channels_non_silent", 1),
        ("observed.media.pcm.media.wav_sha256", "0" * 64),
        ("observed.lifecycle.sessions.0.readiness_frame.sha256", "0" * 64),
        ("observed.lifecycle.sessions.0.readiness_player_ack_sha256", "0" * 64),
        ("observed.lifecycle.sessions.0.readiness_session_id", "f" * 32),
        ("observed.lifecycle.sessions.0.processes.0.pid", 999),
        ("observed.lifecycle.sessions.0.processes.0.start_identity", "f" * 32),
        ("observed.lifecycle.sessions.0.processes.0.owner_run_id", "f" * 32),
        ("observed.lifecycle.sessions.0.processes.0.session_id", "f" * 32),
        ("observed.lifecycle.sessions.0.processes.0.exit_code", 1),
        ("observed.lifecycle.sessions.0.processes.0.reaped", False),
        ("observed.lifecycle.sessions.0.ownership_checked", False),
        ("observed.lifecycle.sessions.0.ipc_removed", False),
        ("observed.lifecycle.sessions.0.volatile_state_removed", False),
        ("observed.lifecycle.sessions.0.resources_released", False),
        ("observed.lifecycle.sessions.1.session_id", "1" * 32),
        ("observed.lifecycle.sessions.1.previous_session_id", "f" * 32),
        ("observed.lifecycle.sessions.1.started_ms", 1800),
        ("observed.lifecycle.sessions.1.initial_state_sha256", "0" * 64),
        ("observed.lifecycle.sessions.2.initial_state_sha256", "0" * 64),
        ("observed.lifecycle.sessions.0.player_ready_ms", 2000),
        ("observed.lifecycle.sessions.0.stopped_ms", 1999 + 500),
    ],
)
def test_report_rejects_promotion_contradiction_and_incomplete_evidence(
    path: str, value: object
) -> None:
    data, _ = journey()
    change(data, path, value)
    with pytest.raises(ValueError, match="invalid stock preparation report"):
        parse(data)


def test_preparation_report_keeps_unknown_identities_and_no_observations() -> None:
    report = preparation_report("a" * 32)
    assert parse_report(report.model_dump_json().encode()) == report
    assert report.observed is None
    assert report.status == "BLOCKED"
    assert report.expected.inputs is report.expected.lifecycle is None
    assert not report.context.identities.complete()


@pytest.mark.parametrize(
    "kind", ["missing", "duplicate-role", "missing-response", "unknown", "malformed-hash"]
)
def test_incomplete_or_unknown_receipts_are_rejected(kind: str) -> None:
    data, _ = journey()
    if kind == "missing":
        del data["observed"]["media"]["pcm"]["pcm_bytes"]
    elif kind == "duplicate-role":
        data["observed"]["lifecycle"]["sessions"][0]["processes"][1]["role"] = "mq_ui"
    elif kind == "missing-response":
        data["observed"]["inputs"].pop()
    elif kind == "unknown":
        data["private_path"] = "not-echoed-private-marker"
    else:
        data["context"]["identities"]["package"]["sha256"] = "not-echoed-private-marker"
    with pytest.raises(ValueError) as error:
        parse(data)
    assert "not-echoed-private-marker" not in str(error.value)


@pytest.mark.parametrize(
    "payload",
    [b"{}", b"[]", b"null", b"{", b"\xff", b"x" * (128 * 1024 + 1), b"[" * 2000],
    ids=["empty-object", "array", "null", "syntax", "non-utf8", "oversize", "deep"],
)
def test_parser_refuses_malformed_bounded_json(payload: bytes) -> None:
    with pytest.raises(ValueError):
        parse_report(payload)


@pytest.mark.parametrize("nested", [False, True])
def test_duplicate_receipt_fields_rejected_recursively(nested: bool) -> None:
    raw = preparation_report("a" * 32).model_dump_json()
    if nested:
        raw = raw.replace('"sha256":null', '"sha256":null,"sha256":null', 1)
    else:
        raw = raw.replace('"verified":false', '"verified":false,"verified":false', 1)
    with pytest.raises(ValueError):
        parse_report(raw.encode())


def test_schema_matches_model_and_accepts_preparation_and_simulated_examples() -> None:
    schema = json.loads(
        (ROOT / "schemas/lab-stock-acceptance-preparation-v1.schema.json").read_text()
    )
    assert schema == StockReport.model_json_schema()
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    for data in (preparation_report("a" * 32).model_dump(), journey()[0]):
        validator.validate(data)
        assert parse(data).stock_execution == "NOT RUN"
    for field, value in (("status", "PASS"), ("verified", True), ("authenticated", 0)):
        data = preparation_report("a" * 32).model_dump()
        data[field] = value
        assert not validator.is_valid(data)
        with pytest.raises(ValueError):
            parse(data)


def test_comparators_revalidate_mutable_or_model_copy_input() -> None:
    data, frames = journey()
    report = parse(data)
    assert report.observed is not None
    assert report.expected.inputs is not None
    report.observed.inputs[0].frame.__dict__["width"] = True
    with pytest.raises(ValueError):
        compare_inputs(
            report.context, "1" * 32, report.expected.inputs, report.observed.inputs, frames
        )
    with pytest.raises(ValueError):
        StockReport.model_validate(report)


def test_direct_media_comparator_rehashes_bytes_and_rejects_partial_track() -> None:
    data, _ = journey()
    observed = data["observed"]
    with pytest.raises(ValueError):
        compare_media(
            Context.model_validate(data["context"]),
            Expected.model_validate(data["expected"]),
            MediaObservation.model_validate(observed["media"]),
            LifecycleObservation.model_validate(observed["lifecycle"]).sessions[0],
            pcm_fixture()[:-4],
        )


def test_fixed_input_plan_refuses_reordering_and_changed_payload() -> None:
    data, _ = journey()
    plan = data["expected"]["inputs"]
    plan["steps"].reverse()
    with pytest.raises(ValueError):
        InputPlan.model_validate(plan)
    with pytest.raises(ValueError):
        input_payload(True)
    with pytest.raises(ValueError):
        input_payload(-1)
