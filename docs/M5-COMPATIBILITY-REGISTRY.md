# M5 compatibility registry foundation

This foundation adds an importable versioned registry model for candidate
compatibility records. It is read-only: callers can validate JSON, query exact
identity fields and compare two scenario records. It does not change the CLI,
existing sanitized receipt reports, or their parser contracts.

Each record names the product, device and hardware revision; main and recovery
firmware; original package, rootfs and stock `mq_player` hashes; runner, runner
revision and shim revision; UI binary and source revision; adapter revision;
scenario and scenario-suite revision; host/runtime context; evidence references;
and limitations. Fields that are unavailable are written as explicit `null`.
The query function treats a null filter as an exact request for unknown data.
Comparison requires every identity component to be known and equal, so two
missing hashes do not stand in for matching artifacts. Version strings alone
never establish compatibility.

Support state and per-scenario outcome are separate vocabularies. Scenario
PASS/FAIL observations can be retained while overall support stays unknown.
`inventoried` records must keep outcomes `NOT RUN`; `rejected` requires a
scenario `FAIL` and a stated reason; `stale` requires a stated limitation.
Upstream claims and Lab observations keep distinct provenance labels, and each
claim must refer to evidence with matching provenance. Those labels are
declarations, not authenticated proof.

Version 1 rejects imports marked `static-compatible`, `partial`,
`verified-emulator` or `verified-device` because it has no trusted evidence
assessment mechanism yet. No `authenticated` input flag is accepted. Synthetic
receipts, manifest statements and other unauthenticated metadata therefore
cannot promote overall support. The full state vocabulary remains modeled for
future authenticated assessment. The registry does not grant execution
authority. Stock V2.57 boot, stock IPC compatibility, and device acceptance
remain `NOT RUN` / unknown unless future independent evidence establishes
otherwise.

JSON is capped at 1 MiB, rejects duplicate keys and unknown fields, and uses
strict typed validation. Registry records and nested collections are immutable
tuples. Public query, serialization and comparison boundaries revalidate
records to catch invalid instances created through Pydantic `model_copy` or
`model_construct`. Output ordering and serialization are deterministic.

Immutable runner, shim, UI source, adapter and scenario revisions must be full
lowercase 40-character Git commits or 64-character digests. The JSON Schema in
`schemas/lab-compatibility-registry-v1.schema.json` is the portable structural
contract. Application validation additionally enforces cross-field rules,
including provenance matching and deferred support-state promotion.
