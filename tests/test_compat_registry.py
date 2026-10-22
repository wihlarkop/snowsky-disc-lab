"""Contract checks for the exact-identity compatibility registry foundation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from snowsky_disc_lab.compat_registry import (
    REGISTRY_SCHEMA,
    CompatibilityRecord,
    RegistryError,
    SupportState,
    build_registry,
    compare_records,
    parse_registry_json,
    query_registry,
    registry_json,
)

_HASH = "a" * 64


def record(
    record_id: str = "candidate",
    scenario_outcome: str = "PASS",
    **identity_updates: object,
) -> CompatibilityRecord:
    identity = {
        "product_id": "snowsky-disc",
        "device_model": "DISC",
        "hardware_revision": "rev-a",
        "firmware_main": "2.57",
        "firmware_recovery": "18",
        "original_firmware_sha256": _HASH,
        "rootfs_sha256": "b" * 64,
        "stock_mq_player_sha256": "c" * 64,
        "runner_id": "qemu-mipsel",
        "runner_revision": "1" * 40,
        "shim_revision": "2" * 40,
        "ui_binary_sha256": "d" * 64,
        "ui_source_revision": "3" * 40,
        "adapter_revision": "4" * 40,
        "scenario_id": "cold-start",
        "scenario_revision": "5" * 40,
        "host_runtime": {
            "os_name": "Linux",
            "os_version": "test-host",
            "architecture": "x86_64",
            "runtime_name": "QEMU",
            "runtime_version": "test-runner",
        },
    }
    identity.update(identity_updates)
    return CompatibilityRecord.model_validate_json(
        json.dumps(
            {
                "record_id": record_id,
                "schema_version": REGISTRY_SCHEMA,
                "identity": identity,
                "support_state": "unknown",
                "scenario_outcome": scenario_outcome,
                "evidence": [
                    {
                        "reference_id": "source",
                        "provenance": "upstream",
                        "kind": "source-claim",
                        "uri": "https://example.invalid/source",
                        "sha256": None,
                    },
                    {
                        "reference_id": "observation",
                        "provenance": "lab-run",
                        "kind": "sanitized-observation",
                        "uri": None,
                        "sha256": _HASH,
                    },
                ],
                "claims_and_observations": [
                    {
                        "field": "firmware_main",
                        "value": "2.57",
                        "provenance": "upstream",
                        "evidence_reference_id": "source",
                    },
                    {
                        "field": "scenario_outcome",
                        "value": scenario_outcome,
                        "provenance": "lab-run",
                        "evidence_reference_id": "observation",
                    },
                ],
                "limitations": ["synthetic evidence only"],
                "execution_authority": False,
            }
        )
    )


def test_registry_round_trip_and_query_order_are_deterministic() -> None:
    first = record("z-record", scenario_id="z-scenario")
    second = record("a-record", scenario_id="a-scenario")
    registry = build_registry([first, second])

    output = registry_json(registry)
    assert output == registry_json(build_registry([second, first]))
    assert output == registry_json(parse_registry_json(output))
    assert [item.record_id for item in query_registry(registry)] == ["a-record", "z-record"]
    assert [item.record_id for item in query_registry(registry, {"rootfs_sha256": None})] == []
    assert [item.record_id for item in query_registry(registry, {"device_model": "DISC"})] == [
        "a-record",
        "z-record",
    ]
    assert [
        item.record_id for item in query_registry(registry, {"host_runtime.os_name": "Linux"})
    ] == ["a-record", "z-record"]

    schema = json.loads(
        Path("schemas/lab-compatibility-registry-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(json.loads(output))


def test_missing_hashes_never_make_comparison_comparable() -> None:
    first = record("first", rootfs_sha256=None)
    later = record("later", rootfs_sha256=None)
    result = compare_records(first, later)
    assert result["comparable"] is False
    assert result["classification"] == "incomparable"
    assert result["overall_support_state"] == "unknown"


def test_exact_identity_mismatch_is_incomparable() -> None:
    result = compare_records(record("one"), record("two", ui_binary_sha256="e" * 64))
    assert result["comparable"] is False
    assert result["classification"] == "incomparable"


def test_exact_identity_comparison_classifies_scenario_regression() -> None:
    result = compare_records(
        record("earlier", scenario_outcome="PASS"),
        record("later", scenario_outcome="FAIL"),
    )
    assert result["comparable"] is True
    assert result["classification"] == "regression"


def test_duplicate_and_contradictory_records_are_rejected() -> None:
    with pytest.raises(RegistryError, match="invalid compatibility registry"):
        build_registry([record("same"), record("same", scenario_id="other")])
    with pytest.raises(RegistryError, match="invalid compatibility registry"):
        build_registry([record("one"), record("two")])


def test_duplicate_json_keys_unknown_fields_and_malformed_hashes_are_rejected() -> None:
    with pytest.raises(RegistryError, match="duplicate JSON key"):
        parse_registry_json('{"schema_version":"x","schema_version":"y","records":[]}')

    payload = json.loads(registry_json(build_registry([record()])))
    payload["surprise"] = True
    with pytest.raises(RegistryError, match="invalid compatibility registry"):
        parse_registry_json(json.dumps(payload))


def test_static_and_partial_claims_cannot_promote_unauthenticated_metadata() -> None:
    for support_state in ("static-compatible", "partial"):
        payload = json.loads(registry_json(build_registry([record()])))
        payload["records"][0]["support_state"] = support_state
        with pytest.raises(RegistryError, match="invalid compatibility registry"):
            parse_registry_json(json.dumps(payload))


def test_provenance_mismatch_empty_identity_and_floating_revisions_are_rejected() -> None:
    payload = json.loads(registry_json(build_registry([record()])))
    payload["records"][0]["claims_and_observations"][0]["provenance"] = "lab-run"
    with pytest.raises(RegistryError, match="invalid compatibility registry"):
        parse_registry_json(json.dumps(payload))

    payload = json.loads(registry_json(build_registry([record()])))
    payload["records"][0]["support_state"] = "rejected"
    payload["records"][0]["scenario_outcome"] = "FAIL"
    payload["records"][0]["claims_and_observations"][1]["value"] = "FAIL"
    assert parse_registry_json(json.dumps(payload)).records[0].support_state.value == "rejected"

    payload = json.loads(registry_json(build_registry([record()])))
    payload["records"][0]["identity"]["device_model"] = "   "
    with pytest.raises(RegistryError, match="invalid compatibility registry"):
        parse_registry_json(json.dumps(payload))

    payload = json.loads(registry_json(build_registry([record()])))
    payload["records"][0]["identity"]["runner_revision"] = "main"
    with pytest.raises(RegistryError, match="invalid compatibility registry"):
        parse_registry_json(json.dumps(payload))

    payload = json.loads(registry_json(build_registry([record()])))
    payload["records"][0]["identity"].pop("firmware_main")
    with pytest.raises(RegistryError, match="invalid compatibility registry"):
        parse_registry_json(json.dumps(payload))

    payload = json.loads(registry_json(build_registry([record()])))
    payload["records"][0]["identity"]["rootfs_sha256"] = "not-a-digest"
    with pytest.raises(RegistryError, match="invalid compatibility registry"):
        parse_registry_json(json.dumps(payload))

    payload = json.loads(registry_json(build_registry([record()])))
    payload["records"][0]["support_state"] = "rejected"
    with pytest.raises(RegistryError, match="invalid compatibility registry"):
        parse_registry_json(json.dumps(payload))

    payload["records"][0]["support_state"] = "static-compatible"
    payload["records"][0]["scenario_outcome"] = "NOT RUN"
    payload["records"][0]["claims_and_observations"] = payload["records"][0][
        "claims_and_observations"
    ][:1]
    with pytest.raises(RegistryError, match="invalid compatibility registry"):
        parse_registry_json(json.dumps(payload))


def test_verified_promotion_laundering_and_bool_integer_trap_are_rejected() -> None:
    payload = json.loads(registry_json(build_registry([record()])))
    candidate = payload["records"][0]
    candidate["support_state"] = SupportState.VERIFIED_EMULATOR.value
    candidate["authenticated"] = True
    with pytest.raises(RegistryError, match="invalid compatibility registry"):
        parse_registry_json(json.dumps(payload))

    candidate.pop("authenticated")
    with pytest.raises(RegistryError, match="invalid compatibility registry"):
        parse_registry_json(json.dumps(payload))

    payload = json.loads(registry_json(build_registry([record()])))
    payload["records"][0]["execution_authority"] = 1
    with pytest.raises(RegistryError, match="invalid compatibility registry"):
        parse_registry_json(json.dumps(payload))


def test_immutable_models_and_model_copy_are_revalidated_at_boundary() -> None:
    candidate = record()
    with pytest.raises(ValidationError):
        candidate.__setattr__("support_state", SupportState.STALE)
    assert isinstance(candidate.evidence, tuple)
    assert isinstance(candidate.claims_and_observations, tuple)

    registry = build_registry([candidate])
    bypassed = registry.model_copy(update={"records": (candidate, candidate)})
    with pytest.raises(RegistryError, match="invalid compatibility registry"):
        query_registry(bypassed)
    forged_registry = registry.model_copy(
        update={"records": (candidate.model_copy(update={"support_state": SupportState.PARTIAL}),)}
    )
    with pytest.raises(RegistryError, match="invalid compatibility registry"):
        build_registry(forged_registry.records)
    forged = candidate.model_copy(update={"support_state": SupportState.VERIFIED_EMULATOR})
    with pytest.raises(RegistryError, match="invalid comparison record"):
        compare_records(candidate, forged)


def test_filter_names_are_strict() -> None:
    registry = build_registry([record()])
    with pytest.raises(RegistryError, match="unknown identity filter"):
        query_registry(registry, {"firmware_version": "2.57"})
