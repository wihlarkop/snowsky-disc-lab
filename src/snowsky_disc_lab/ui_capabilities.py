"""Firmware-free capability declarations and deterministic preflight refusals.

The caller supplies observations. Neither this module nor its input contracts
authenticate evidence, inspect a runner, or grant execution authority.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

type CapabilityName = Literal[
    "framebuffer-360",
    "input-touch",
    "physical-keys",
    "mqueue-player",
    "library-scan",
    "pcm-local",
    "playlist-queue",
    "artwork-render",
    "power-lifecycle",
    "radio-network",
    "signed-ui-update",
]
type ObservationOutcome = Literal["observed", "unsupported", "blocked", "not-run"]
type ObservationReason = Literal[
    "runtime-feature-unavailable",
    "missing-stock-baseline",
    "missing-runner-feature",
    "missing-authorization",
    "missing-identity",
    "missing-readiness",
    "missing-evidence",
]
type ReviewOutcome = Literal["OBSERVED", "UNSUPPORTED", "BLOCKED", "NOT RUN", "UNKNOWN"]
type RefusalCode = Literal[
    "ui-undeclared",
    "ui-unsupported",
    "runtime-unsupported",
    "prerequisite-blocked",
    "observation-not-run",
]
type ContractRefusalCode = Literal[
    "invalid-structure",
    "unsupported-version",
    "unknown-capability",
    "conflicting-declaration",
    "contradictory-observation",
]

CAPABILITY_NAMES: tuple[CapabilityName, ...] = (
    "framebuffer-360",
    "input-touch",
    "physical-keys",
    "mqueue-player",
    "library-scan",
    "pcm-local",
    "playlist-queue",
    "artwork-render",
    "power-lifecycle",
    "radio-network",
    "signed-ui-update",
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class CapabilityDeclaration(_StrictModel):
    """A UI author's intent, separate from lab-ui/v1 firmware claims."""

    apiVersion: Literal["lab-ui-capabilities/v1"]
    kind: Literal["UICapabilities"]
    declared: Annotated[list[CapabilityName], Field(max_length=len(CAPABILITY_NAMES))]
    unsupported: Annotated[list[CapabilityName], Field(max_length=len(CAPABILITY_NAMES))]

    @model_validator(mode="after")
    def reject_repeated_or_conflicting_names(self) -> CapabilityDeclaration:
        if len(set(self.declared)) != len(self.declared):
            raise ValueError("duplicate declared capability")
        if len(set(self.unsupported)) != len(self.unsupported):
            raise ValueError("duplicate unsupported capability")
        if set(self.declared) & set(self.unsupported):
            raise ValueError("capability cannot be declared and unsupported")
        return self


class CapabilityObservation(_StrictModel):
    """Caller-supplied observation state; no evidence authentication implied."""

    name: CapabilityName
    outcome: ObservationOutcome
    reason: ObservationReason | None

    @model_validator(mode="after")
    def require_consistent_reason(self) -> CapabilityObservation:
        blocked_reasons = {
            "missing-stock-baseline",
            "missing-runner-feature",
            "missing-authorization",
            "missing-identity",
            "missing-readiness",
            "missing-evidence",
        }
        if self.outcome == "blocked" and self.reason not in blocked_reasons:
            raise ValueError("blocked observation needs a blocked prerequisite reason")
        if self.outcome == "unsupported" and self.reason != "runtime-feature-unavailable":
            raise ValueError("unsupported observation needs runtime-feature-unavailable")
        if self.outcome in {"observed", "not-run"} and self.reason is not None:
            raise ValueError("observed and not-run outcomes cannot have refusal reasons")
        return self


class CapabilityReview(_StrictModel):
    """Fixed requests and caller-supplied observation states for a preflight review."""

    apiVersion: Literal["lab-ui-capability-review/v1"]
    kind: Literal["UICapabilityReview"]
    required: Annotated[list[CapabilityName], Field(max_length=len(CAPABILITY_NAMES))]
    optional: Annotated[list[CapabilityName], Field(max_length=len(CAPABILITY_NAMES))]
    observations: Annotated[list[CapabilityObservation], Field(max_length=len(CAPABILITY_NAMES))]

    @model_validator(mode="after")
    def reject_repeated_names(self) -> CapabilityReview:
        if not self.required and not self.optional:
            raise ValueError("review must request at least one capability")
        if len(set(self.required)) != len(self.required):
            raise ValueError("duplicate required capability")
        if len(set(self.optional)) != len(self.optional):
            raise ValueError("duplicate optional capability")
        if set(self.required) & set(self.optional):
            raise ValueError("capability cannot be both required and optional")
        names = [item.name for item in self.observations]
        if len(set(names)) != len(names):
            raise ValueError("duplicate capability observation")
        if not set(names) <= set(self.required) | set(self.optional):
            raise ValueError("observation outside requested capability set")
        return self


class CapabilityResult(_StrictModel):
    name: CapabilityName
    required: bool
    declared: bool
    observation: ObservationOutcome | None
    observationReason: ObservationReason | None
    outcome: ReviewOutcome
    refusalCode: RefusalCode | None
    handling: Literal["observed", "refuse", "skip"]

    @model_validator(mode="after")
    def reject_inconsistent_result(self) -> CapabilityResult:
        expected: dict[
            ReviewOutcome, tuple[bool, set[ObservationOutcome | None], RefusalCode | None]
        ] = {
            "OBSERVED": (True, {"observed"}, None),
            "BLOCKED": (True, {"blocked"}, "prerequisite-blocked"),
            "NOT RUN": (True, {None, "not-run"}, "observation-not-run"),
            "UNKNOWN": (False, {None}, "ui-undeclared"),
        }
        if self.outcome == "UNSUPPORTED":
            valid = (
                not self.declared
                and self.observation is None
                and self.refusalCode == "ui-unsupported"
            ) or (
                self.declared
                and self.observation == "unsupported"
                and self.refusalCode == "runtime-unsupported"
            )
        else:
            declared, observations, refusal = expected[self.outcome]
            valid = (
                self.declared == declared
                and self.observation in observations
                and self.refusalCode == refusal
            )
        if not valid:
            raise ValueError("capability outcome contradicts declaration or observation")
        expected_handling = (
            "observed" if self.outcome == "OBSERVED" else "refuse" if self.required else "skip"
        )
        if self.handling != expected_handling:
            raise ValueError("capability handling contradicts required status")
        if self.observation == "blocked" and self.observationReason not in {
            "missing-stock-baseline",
            "missing-runner-feature",
            "missing-authorization",
            "missing-identity",
            "missing-readiness",
            "missing-evidence",
        }:
            raise ValueError("blocked outcome needs a prerequisite reason")
        if (
            self.observation == "unsupported"
            and self.observationReason != "runtime-feature-unavailable"
        ):
            raise ValueError("unsupported outcome needs runtime-feature-unavailable")
        if self.observation in {None, "observed", "not-run"} and self.observationReason is not None:
            raise ValueError("non-refusal observation cannot have a reason")
        return self


class CapabilityAssessment(_StrictModel):
    apiVersion: Literal["lab-ui-capability-assessment/v1"]
    kind: Literal["UICapabilityAssessment"]
    results: Annotated[list[CapabilityResult], Field(max_length=len(CAPABILITY_NAMES))]
    refusalCodes: list[RefusalCode]
    skipCodes: list[RefusalCode]
    launchAuthorized: Literal[False] = False

    @model_validator(mode="after")
    def reject_inconsistent_summary(self) -> CapabilityAssessment:
        names = [item.name for item in self.results]
        if names != [name for name in CAPABILITY_NAMES if name in names]:
            raise ValueError("capability results must use fixed order without duplicates")
        refusal_codes = list(
            dict.fromkeys(item.refusalCode for item in self.results if item.handling == "refuse")
        )
        skip_codes = list(
            dict.fromkeys(item.refusalCode for item in self.results if item.handling == "skip")
        )
        if self.refusalCodes != refusal_codes or self.skipCodes != skip_codes:
            raise ValueError("refusal or skip codes contradict capability results")
        return self


class CapabilityRefusal(_StrictModel):
    apiVersion: Literal["lab-ui-capability-refusal/v1"]
    kind: Literal["UICapabilityRefusal"]
    code: ContractRefusalCode
    field: Annotated[
        str,
        StringConstraints(
            strict=True,
            max_length=64,
            pattern=(
                r"^(?:contract|apiVersion|kind|declared|unsupported|required|optional|observations)"
                r"(?:\.(?:[0-9]+|name|outcome|reason))*$"
            ),
        ),
    ]


class CapabilityContractError(ValueError):
    """Sanitized machine-readable refusal of malformed contract input."""

    def __init__(self, code: ContractRefusalCode, field: str):
        self.code = code
        self.field = field
        super().__init__(f"{code}: {field}")

    def as_dict(self) -> dict[str, str]:
        return CapabilityRefusal(
            apiVersion="lab-ui-capability-refusal/v1",
            kind="UICapabilityRefusal",
            code=self.code,
            field=self.field,
        ).model_dump()


def _safe_field(location: tuple[object, ...]) -> str:
    """Map validation locations to schema-safe fixed paths, never input keys."""
    if not location or not isinstance(location[0], str):
        return "contract"
    root = location[0]
    if root in {"apiVersion", "kind"}:
        return root if len(location) == 1 else "contract"
    if root in {"declared", "unsupported", "required", "optional"}:
        if len(location) == 1:
            return root
        if len(location) == 2 and isinstance(location[1], int):
            return f"{root}.{location[1]}"
        return root
    if root == "observations":
        if len(location) == 1:
            return root
        if not isinstance(location[1], int):
            return root
        indexed = f"observations.{location[1]}"
        if len(location) == 2:
            return indexed
        if len(location) == 3 and location[2] in {"name", "outcome", "reason"}:
            return f"{indexed}.{location[2]}"
        return indexed
    return "contract"


def _parse(model: type[CapabilityDeclaration] | type[CapabilityReview], data: object):
    try:
        return model.model_validate(data)
    except ValidationError as error:
        issue = error.errors(include_url=False, include_context=False, include_input=False)[0]
        location = issue["loc"]
        field = _safe_field(tuple(location))
        if location and location[0] == "apiVersion":
            code: ContractRefusalCode = "unsupported-version"
        elif (
            issue["type"] == "literal_error"
            and location
            and (
                location[0] in {"declared", "unsupported", "required", "optional"}
                or location[-1] == "name"
            )
        ):
            code = "unknown-capability"
        elif issue["type"] == "value_error":
            code = "conflicting-declaration"
        else:
            code = "invalid-structure"
        raise CapabilityContractError(code, field) from None


def parse_declaration(data: object) -> CapabilityDeclaration:
    """Validate an untrusted declaration without echoing its values."""
    result = _parse(CapabilityDeclaration, data)
    assert isinstance(result, CapabilityDeclaration)
    return result


def parse_review(data: object) -> CapabilityReview:
    """Validate review input without promoting observations to verified evidence."""
    result = _parse(CapabilityReview, data)
    assert isinstance(result, CapabilityReview)
    return result


def assess_capabilities(
    declaration: CapabilityDeclaration, review: CapabilityReview
) -> CapabilityAssessment:
    """Return stable outcomes in fixed capability-name order; never authorize launch."""
    if not isinstance(declaration, CapabilityDeclaration) or not isinstance(
        review, CapabilityReview
    ):
        raise CapabilityContractError("invalid-structure", "contract")
    # Pydantic's frozen models can still contain mutable lists, and model_copy
    # does not validate updates. Reparse before making any decision.
    declaration = parse_declaration(declaration.model_dump(warnings="none"))
    review = parse_review(review.model_dump(warnings="none"))
    observations = {item.name: item.outcome for item in review.observations}
    if any(name not in declaration.declared for name in observations):
        raise CapabilityContractError("contradictory-observation", "observations")
    results: list[CapabilityResult] = []
    codes: list[RefusalCode] = []
    skip_codes: list[RefusalCode] = []
    for name in CAPABILITY_NAMES:
        if name not in review.required and name not in review.optional:
            continue
        required = name in review.required
        declared = name in declaration.declared
        observation = observations.get(name)
        outcome: ReviewOutcome
        refusal: RefusalCode | None
        if name in declaration.unsupported:
            outcome, refusal = "UNSUPPORTED", "ui-unsupported"
        elif not declared:
            outcome, refusal = "UNKNOWN", "ui-undeclared"
        elif observation == "unsupported":
            outcome, refusal = "UNSUPPORTED", "runtime-unsupported"
        elif observation == "blocked":
            outcome, refusal = "BLOCKED", "prerequisite-blocked"
        elif observation == "observed":
            outcome, refusal = "OBSERVED", None
        else:
            outcome, refusal = "NOT RUN", "observation-not-run"
        results.append(
            CapabilityResult(
                name=name,
                required=required,
                declared=declared,
                observation=observation,
                observationReason=next(
                    (item.reason for item in review.observations if item.name == name), None
                ),
                outcome=outcome,
                refusalCode=refusal,
                handling="observed" if refusal is None else "refuse" if required else "skip",
            )
        )
        if refusal is not None:
            selected = codes if required else skip_codes
            if refusal not in selected:
                selected.append(refusal)
    return CapabilityAssessment(
        apiVersion="lab-ui-capability-assessment/v1",
        kind="UICapabilityAssessment",
        results=results,
        refusalCodes=codes,
        skipCodes=skip_codes,
    )
