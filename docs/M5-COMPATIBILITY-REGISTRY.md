# M5 compatibility registry foundation

This foundation adds an importable versioned registry model for candidate
compatibility records. It is read-only: callers can validate JSON, query exact
identity fields and compare two scenario records. The registry CLI reads explicitly selected local JSON files; existing sanitized
receipt reports and their parser contracts retain their behavior.

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


## Read-only registry CLI

```console
disc-lab compat list REGISTRY.json --format json
disc-lab compat list REGISTRY.json --format markdown
disc-lab compat show REGISTRY.json --id RECORD_ID --format json
disc-lab compat show REGISTRY.json --id RECORD_ID --format markdown
```

Markdown is the default. List JSON uses the unchanged registry v1 schema, sorted
by exact record ID. Show JSON returns the selected complete record with unchanged
identity, provenance, nulls and authority fields. IDs are case-sensitive and are
never trimmed or matched approximately. Markdown shows every identity field
(null becomes `unknown`), support separately from scenario outcome, separate
upstream claims and Lab observations, evidence references and limitations.
Untrusted text is escaped and control characters are neutralized; evidence URIs
are displayed as text and never fetched or opened. Provenance labels remain
unauthenticated declarations. No accepted record authorizes execution or proves
stock compatibility, including when a synthetic scenario reports PASS.

Exit status is 0 for successful rendering (including an empty list), 1 when a
valid registry has no exact requested ID, and 2 for malformed command arguments,
unsafe/missing/unreadable paths, oversized or invalid registry input. Refusal
messages do not echo private paths, IDs or untrusted parser details. Only the
selected file is read: there is no discovery, network request, database, service
or registry mutation. Local regular files are required; network paths, alternate
streams, device names, symlink/reparse-point ancestors and special files are
refused before reading. A trusted, quiescent filesystem owner is assumed; these
checks do not defend against a hostile same-user concurrent path swap.

The 1 MiB UTF-8 limit applies both to imported JSON and canonical generated JSON,
including indentation and the final newline. `build_registry` and `registry_json`
reject generated output beyond this limit, including models constructed through
Pydantic validation bypasses. Accepted generated registries remain readable by
`parse_registry_json` without a schema change. Serialization is deterministic;
query/assessment features and authenticated promotion remain separate work.

This closes the list/show portion of M5-04. It does not complete M5, authenticate
runtime evidence, execute fixtures, or establish stock V2.57 boot, stock IPC or
physical-device acceptance. Those gates remain NOT RUN / UNVERIFIED.
