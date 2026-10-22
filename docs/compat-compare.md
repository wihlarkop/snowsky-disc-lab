# Comparing compatibility reports

`snowsky_disc_lab.compat_compare.compare_reports` compares two dictionaries
already produced by the sanitized compatibility receipt parser. It is
deterministic, read-only, and performs no receipt parsing, filesystem access,
runtime execution, or artifact hashing.

Comparison conditions match only when both reports declare the same receipt
schema, the exact same artifact identity mapping (including `qemu-mipsel`),
and the same QEMU `build_source` identity, including matching presence or
absence. Any mismatch makes every scenario result `incomparable`; reports from
different QEMU build sources or artifact identities are never presented as
same-condition evidence. Present build-source identities are structurally
validated before comparison.

With matching conditions, `PASS` to `FAIL` is a regression and `FAIL` to
`PASS` is an improvement. Equal outcomes are unchanged. Other differing
outcomes, including transitions involving `NOT RUN`, `BLOCKED`, or
`UNSUPPORTED`, are incomparable. A scenario absent from either report is
treated as `NOT RUN`, never as `PASS`. Stock firmware boot and IPC scenarios
must remain `NOT RUN`; a contradictory report is rejected.

The structured output retains a copy of the earlier report as historical
evidence, includes the later source label, and carries the earlier receipt's
declared/unauthenticated provenance. The scope remains firmware-free synthetic
execution and overall support remains unknown. Stock firmware compatibility
is still unknown and not run.

Malformed inputs, unknown statuses, invalid identities, and contradictory
stock firmware results raise `CompatibilityComparisonError`.

## CLI comparison

Compare exactly two local sanitized receipts with:

```console
disc-lab compat compare EARLIER.json LATER.json --format json
disc-lab compat compare EARLIER.json LATER.json --format markdown
```

Markdown is the default. The command uses bounded reads and rejects a regular
file larger than the 1 MiB `MAX_RECEIPT_BYTES` limit. UNC and Windows network
namespace paths are refused before filesystem access. It uses the same strict
receipt parser as `compat report`. JSON retains both parsed receipts, both
complete artifact identity maps, the scenario history, and any declared QEMU
build-source identities. Markdown shows both artifact maps, each scenario's
earlier and later status, classification, and discrepancy reason, plus both
QEMU source identities when present.

Source labels are the neutral words `earlier` and `later`; local paths and raw
parser errors are not included in output. Missing, malformed, contradictory,
or oversized receipts exit with status 2 and a concise error. Receipt values
remain declared and unauthenticated, artifact bytes are not rehashed, missing
scenarios are `NOT RUN`, stock V2.57 compatibility remains `UNKNOWN / NOT RUN`,
and overall support remains `unknown`.

## Opt-in regression diagnostics

The comparison's existing JSON and Markdown contracts stay unchanged by
default. Add `--diagnostics` to include the separately versioned
`firmware-free-synthetic-compatibility-diagnostics/v1` surface:

```console
disc-lab compat compare EARLIER.json LATER.json --format json --diagnostics
disc-lab compat compare EARLIER.json LATER.json --diagnostics
```

Diagnostics list only comparable `PASS` to `FAIL` transitions. A differing
receipt schema, artifact identity, or build-source identity yields
`status: incomparable` and no domain findings. Improvements, missing
scenarios, `BLOCKED`, `UNSUPPORTED`, and other status transitions remain
visible in the existing comparison and are not relabeled as regressions.

The domain vocabulary is `build`, `abi`, `input`, `framebuffer`, `ipc`,
`audio`, `power-lifecycle`, and `environment`. The current parser evidence
supports one specific mapping: `synthetic-ipc-handoff` maps to `ipc` only when
the fixed handoff evidence marker, nested status, both roles, the one or two
sessions allowed by the parsed failure lifecycle, and QEMU/guest identity
links agree in both reports. Other scenario regressions
remain `UNCLASSIFIED`; missing or free-form evidence never selects a domain.
No current scenario supports a defensible mapping to the other seven domains.

The new surface is deterministic and does not edit receipt inputs. Its
diagnoses describe only declared, unauthenticated firmware-free synthetic
evidence. They do not establish stock firmware behavior, emulator support,
device support, or any previously unrun scenario.
