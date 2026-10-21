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
