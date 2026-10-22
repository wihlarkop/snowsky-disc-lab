# M2-05 external UI capability boundary

This firmware-free Python boundary records what a UI author declares, what a
caller reports observing, and why a requested capability must be refused or
left untested. It performs no binary launch, QEMU probe, firmware intake, or
evidence authentication. Its assessments always set `launchAuthorized: false`.
The first-party JSON examples are contract fixtures, not Lab runtime results.

## Contracts and fixed names

The public contracts are versioned independently of `lab-ui/v1`:

| Structure | Version | Purpose |
| --- | --- | --- |
| [UI capability declaration](../schemas/lab-ui-capabilities-v1.schema.json) | `lab-ui-capabilities/v1` | `declared` is UI author intent; `unsupported` is an explicit UI exclusion. |
| [Capability review](../schemas/lab-ui-capability-review-v1.schema.json) | `lab-ui-capability-review/v1` | Disjoint required/optional names and caller-supplied observation outcomes. |
| [Capability assessment](../schemas/lab-ui-capability-assessment-v1.schema.json) | `lab-ui-capability-assessment/v1` | Deterministic outcomes, handling, refusal codes and skip codes. |
| [Contract refusal](../schemas/lab-ui-capability-refusal-v1.schema.json) | `lab-ui-capability-refusal/v1` | Sanitized error code and fixed field location for malformed input. |

Allowed capability names are exactly `framebuffer-360`, `input-touch`,
`physical-keys`, `mqueue-player`, `library-scan`, `pcm-local`,
`playlist-queue`, `artwork-render`, `power-lifecycle`, `radio-network`,
and `signed-ui-update`, as listed in [compatibility](COMPATIBILITY.md#4-capability-based-compatibility).
Names, versions, kinds, outcome values, and prerequisite reasons are fixed.
Extra fields, duplicates, overlapping `declared`/`unsupported` or
`required`/`optional` lists, missing fields, and unknown names are refused.
Both inputs are revalidated when assessed
so mutation after parsing cannot change a decision silently.

`lab-ui/v1` keeps all its required fields and their meanings. Its
`claims.firmware` remains an author's firmware claim only. This separate
declaration does not turn that claim into an observation or a compatibility
record. It does not grant a UI, including Sorane, any special privilege.

## Outcomes

| Assessment outcome | Meaning | Refusal code |
| --- | --- | --- |
| `OBSERVED` | The UI declared the capability and the caller supplied `observed`. The input remains unauthenticated. | none |
| `UNSUPPORTED` | The UI explicitly excludes it, or the caller reports a runtime feature unavailable. | `ui-unsupported` or `runtime-unsupported` |
| `BLOCKED` | A declared capability lacks a prerequisite identified by a fixed reason. | `prerequisite-blocked` |
| `NOT RUN` | Declared, but no observation exists or the caller supplied `not-run`. | `observation-not-run` |
| `UNKNOWN` | The UI neither declares nor explicitly excludes it. | `ui-undeclared` |

Blocked reasons are `missing-stock-baseline`, `missing-runner-feature`,
`missing-authorization`, `missing-identity`, `missing-readiness`, and
`missing-evidence`. Runtime `unsupported` requires
`runtime-feature-unavailable`; `observed` and `not-run` have a null reason.
An observation supplied for a capability the UI did not declare is refused as
`contradictory-observation`. Required missing capabilities have `handling:
"refuse"` and appear in `refusalCodes`; optional ones have `handling: "skip"`
and appear in `skipCodes`. An observed capability has `handling: "observed"`.
This is planning disposition only, not an executable launch decision. The
contract error is machine-readable:
`CapabilityContractError.as_dict()` returns the versioned
`lab-ui-capability-refusal/v1` structure with sanitized `code` and `field`,
without echoing input values. Its fixed codes are `invalid-structure`,
`unsupported-version`, `unknown-capability`, `conflicting-declaration`, and
`contradictory-observation`. Assessment results and unique refusal codes use
the fixed capability order, regardless of input order.

The example [declaration](../examples/ui-capabilities-synthetic.json) and
[review](../examples/ui-capability-review-synthetic.json) can be parsed with:

```python
from snowsky_disc_lab.ui_capabilities import (
    assess_capabilities,
    parse_declaration,
    parse_review,
)

assessment = assess_capabilities(parse_declaration(declaration_data), parse_review(review_data))
report = assessment.model_dump()
```

`parse_declaration` and `parse_review` accept decoded Python data, not a file
path. Any future file/JSON ingestion must retain bounded reads and duplicate-key
rejection. No CLI command is added in M2-05.

## Future adapter use

M2-01 can consume this assessment during `preflight` after it separately
validates the exact UI/ELF identity, firmware, runner, recipe, provenance, and
authorization. It must use trusted, evidence-linked observations for the exact
combination, not accept an author's review payload as proof. Every `UNKNOWN`,
`NOT RUN`, `BLOCKED`, and `UNSUPPORTED` result has an explicit refusal for a
required feature or graceful skip for an optional feature; it cannot be converted to
success. Even all `OBSERVED` here never authorizes launch or sets
`verified-emulator` or `verified-device`.

M2-04 must still establish exclusive cold-session ownership, readiness,
private IPC/framebuffer/input resources, supervised stop and cleanup, and
stock-backend evidence before launching an external UI. The current
[handoff ADR](adr/0001-external-ui-handoff.md) keeps warm replacement deferred.
Actual stock V2.57 custom UI and physical device compatibility remain **NOT
RUN**. M2-06/M2-07 may later expose these rules through a synthetic UI fixture
and CLI without changing `lab-ui/v1` or weakening runtime gates.
