from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import validate
from pydantic import ValidationError

from snowsky_disc_lab.ui_capabilities import (
    CAPABILITY_NAMES,
    CapabilityAssessment,
    CapabilityContractError,
    CapabilityRefusal,
    assess_capabilities,
    parse_declaration,
    parse_review,
)

ROOT = Path(__file__).resolve().parents[1]


def _declaration() -> dict[str, object]:
    return json.loads((ROOT / "examples/ui-capabilities-synthetic.json").read_text("utf-8"))


def _review() -> dict[str, object]:
    return json.loads((ROOT / "examples/ui-capability-review-synthetic.json").read_text("utf-8"))


def test_synthetic_fixture_distinguishes_all_five_states_and_refuses_launch() -> None:
    declaration = parse_declaration(_declaration())
    review = _review()
    review["required"] = [*CAPABILITY_NAMES]
    assessment = assess_capabilities(declaration, parse_review(review))

    by_name = {item.name: item for item in assessment.results}
    assert by_name["framebuffer-360"].outcome == "OBSERVED"
    assert by_name["input-touch"].outcome == "NOT RUN"
    assert by_name["mqueue-player"].outcome == "BLOCKED"
    assert by_name["mqueue-player"].observationReason == "missing-stock-baseline"
    assert by_name["radio-network"].outcome == "UNSUPPORTED"
    assert by_name["physical-keys"].outcome == "UNKNOWN"
    assert assessment.refusalCodes == [
        "observation-not-run",
        "ui-undeclared",
        "prerequisite-blocked",
        "ui-unsupported",
    ]
    assert assessment.skipCodes == []
    assert by_name["radio-network"].handling == "refuse"
    assert assessment.launchAuthorized is False
    assert assessment.model_dump()["apiVersion"] == "lab-ui-capability-assessment/v1"


def test_runtime_unavailable_is_unsupported_even_when_ui_declares_it() -> None:
    review = _review()
    review["observations"] = [
        {
            "name": "framebuffer-360",
            "outcome": "unsupported",
            "reason": "runtime-feature-unavailable",
        }
    ]
    assessment = assess_capabilities(parse_declaration(_declaration()), parse_review(review))
    item = assessment.results[0]
    assert item.name == "framebuffer-360"
    assert item.outcome == "UNSUPPORTED"
    assert item.refusalCode == "runtime-unsupported"
    assert item.observationReason == "runtime-feature-unavailable"


def test_optional_unsupported_and_untested_capabilities_skip_explicitly() -> None:
    review = _review()
    review["required"] = ["framebuffer-360"]
    review["optional"] = ["radio-network", "physical-keys", "input-touch"]
    review["observations"] = [
        {"name": "framebuffer-360", "outcome": "observed", "reason": None},
        {"name": "input-touch", "outcome": "not-run", "reason": None},
    ]
    assessment = assess_capabilities(parse_declaration(_declaration()), parse_review(review))
    by_name = {item.name: item for item in assessment.results}
    assert assessment.refusalCodes == []
    assert assessment.skipCodes == ["observation-not-run", "ui-undeclared", "ui-unsupported"]
    assert by_name["framebuffer-360"].handling == "observed"
    assert by_name["input-touch"].handling == "skip"
    assert by_name["physical-keys"].handling == "skip"
    assert by_name["radio-network"].handling == "skip"
    assert assessment.launchAuthorized is False


def test_input_order_does_not_change_machine_readable_result() -> None:
    declaration = _declaration()
    review = _review()
    first = assess_capabilities(parse_declaration(declaration), parse_review(review))
    declared = declaration["declared"]
    required = review["required"]
    observations = review["observations"]
    assert isinstance(declared, list)
    assert isinstance(required, list)
    assert isinstance(observations, list)
    declaration["declared"] = declared[::-1]
    review["required"] = required[::-1]
    review["optional"] = []
    review["observations"] = observations[::-1]
    second = assess_capabilities(parse_declaration(declaration), parse_review(review))
    assert first.model_dump_json() == second.model_dump_json()


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"apiVersion": "lab-ui-capabilities/v2"}, "unsupported-version"),
        ({"declared": ["unreviewed-device"]}, "unknown-capability"),
        ({"declared": ["input-touch", "input-touch"]}, "conflicting-declaration"),
        ({"declared": ["input-touch"], "unsupported": ["input-touch"]}, "conflicting-declaration"),
        ({"declared": "input-touch"}, "invalid-structure"),
        ({"launchCommand": "unsafe"}, "invalid-structure"),
    ],
)
def test_invalid_declarations_have_sanitized_codes(change: dict[str, object], code: str) -> None:
    declaration = _declaration()
    declaration.update(change)
    with pytest.raises(CapabilityContractError) as error:
        parse_declaration(declaration)
    assert error.value.code == code
    assert "unreviewed-device" not in str(error.value)
    assert "unsafe" not in str(error.value)
    refusal = error.value.as_dict()
    assert refusal["apiVersion"] == "lab-ui-capability-refusal/v1"
    assert refusal["kind"] == "UICapabilityRefusal"
    assert set(refusal) == {"apiVersion", "kind", "code", "field"}
    CapabilityRefusal.model_validate(refusal)


@pytest.mark.parametrize(
    "observations",
    [
        [{"name": "framebuffer-360", "outcome": "blocked", "reason": None}],
        [{"name": "framebuffer-360", "outcome": "unsupported", "reason": None}],
        [{"name": "framebuffer-360", "outcome": "observed", "reason": "missing-identity"}],
        [{"name": "framebuffer-360", "outcome": "pass", "reason": None}],
        [{"name": "framebuffer-360", "outcome": "observed", "reason": None}] * 2,
    ],
)
def test_invalid_or_contradictory_observations_are_refused(
    observations: list[dict[str, object]],
) -> None:
    review = _review()
    review["observations"] = observations
    with pytest.raises(CapabilityContractError):
        parse_review(review)


def test_observed_capability_without_ui_declaration_is_refused() -> None:
    review = _review()
    review["required"] = ["physical-keys"]
    review["observations"] = [{"name": "physical-keys", "outcome": "observed", "reason": None}]
    with pytest.raises(CapabilityContractError) as error:
        assess_capabilities(parse_declaration(_declaration()), parse_review(review))
    assert error.value.code == "contradictory-observation"


def test_required_optional_overlap_is_refused() -> None:
    review = _review()
    review["optional"] = ["framebuffer-360"]
    with pytest.raises(CapabilityContractError):
        parse_review(review)


def test_mutated_validated_models_are_rechecked_at_assessment_boundary() -> None:
    declaration = parse_declaration(_declaration())
    review = parse_review(_review())
    declaration.declared.append("radio-network")
    with pytest.raises(CapabilityContractError) as error:
        assess_capabilities(declaration, review)
    assert error.value.code == "conflicting-declaration"

    declaration = parse_declaration(_declaration())
    review = parse_review(_review())
    review.required.append("framebuffer-360")
    with pytest.raises(CapabilityContractError):
        assess_capabilities(declaration, review)

    declaration = parse_declaration(_declaration()).model_copy(
        update={"declared": ["radio-network"]}
    )
    with pytest.raises(CapabilityContractError):
        assess_capabilities(declaration, parse_review(_review()))


def test_public_assessment_rejects_forged_success_and_summary() -> None:
    assessment = assess_capabilities(parse_declaration(_declaration()), parse_review(_review()))
    payload = assessment.model_dump()
    payload["results"][0]["outcome"] = "OBSERVED"
    payload["results"][0]["observation"] = "not-run"
    with pytest.raises(ValidationError):
        CapabilityAssessment.model_validate(payload)

    payload = assessment.model_dump()
    payload["refusalCodes"] = []
    with pytest.raises(ValidationError):
        CapabilityAssessment.model_validate(payload)

    payload = assessment.model_dump()
    payload["launchAuthorized"] = True
    with pytest.raises(ValidationError):
        CapabilityAssessment.model_validate(payload)


def test_checked_in_public_schemas_match_models_and_fixtures() -> None:
    declaration_schema = json.loads(
        (ROOT / "schemas/lab-ui-capabilities-v1.schema.json").read_text("utf-8")
    )
    review_schema = json.loads(
        (ROOT / "schemas/lab-ui-capability-review-v1.schema.json").read_text("utf-8")
    )
    assessment_schema = json.loads(
        (ROOT / "schemas/lab-ui-capability-assessment-v1.schema.json").read_text("utf-8")
    )
    refusal_schema = json.loads(
        (ROOT / "schemas/lab-ui-capability-refusal-v1.schema.json").read_text("utf-8")
    )
    from snowsky_disc_lab.ui_capabilities import CapabilityDeclaration, CapabilityReview

    assert declaration_schema == CapabilityDeclaration.model_json_schema()
    assert review_schema == CapabilityReview.model_json_schema()
    assert assessment_schema == CapabilityAssessment.model_json_schema()
    assert refusal_schema == CapabilityRefusal.model_json_schema()
    validate(_declaration(), declaration_schema)
    validate(_review(), review_schema)
    assessment = assess_capabilities(parse_declaration(_declaration()), parse_review(_review()))
    validate(assessment.model_dump(), assessment_schema)
    invalid = _declaration()
    invalid["declared"] = ["unreviewed-device"]
    with pytest.raises(CapabilityContractError) as error:
        parse_declaration(invalid)
    validate(error.value.as_dict(), refusal_schema)
    assert declaration_schema["additionalProperties"] is False
    assert review_schema["additionalProperties"] is False
    assert assessment_schema["additionalProperties"] is False
    assert refusal_schema["additionalProperties"] is False
