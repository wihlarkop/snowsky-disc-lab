# Source-only distribution readiness

`snowsky_disc_lab.distribution_preflight.assess_distribution_readiness(root)` is a
read-only metadata preflight for a possible future source-only distribution. It
checks `upstreams.lock.yaml` against `docs/license-inventory.json`, including
source IDs and commits, projected paths, pinned evidence URLs, selected license
text digests, and required lock-to-inventory license evidence. It does not read
the projected upstream files or check their bytes.

The JSON and Markdown renderers are deterministic. They contain validated source
IDs and commits plus fixed finding messages; they omit untrusted inventory notes,
component labels, local paths, and control text. A report is a metadata
consistency result, not legal advice or file-level clearance. It does not inspect
or prepare a package, download dependencies, select a Lab root license, or
publish anything.

Findings use four states:

| State | Meaning |
| --- | --- |
| `IDENTIFIED` | The named metadata or boundary is explicitly represented and consistent. |
| `PENDING_REVIEW` | Evidence, attribution, scope, or a distribution decision remains unresolved. |
| `UNKNOWN` | The metadata assessment cannot establish the requested conclusion. |
| `BLOCKED` | Input structure, schema version, source identity, or evidence consistency is invalid. |

The report currently remains `PENDING_REVIEW`. `NOASSERTION` rows and rows
marked pending stay unresolved. The unset Lab root license, optional dependency
licenses, QEMU patch provenance and target-license review, and component-level
notice/file-scope checks remain open. Public repository access and an upstream
repository license do not by themselves grant rights to redistribute every
component.

Vendor firmware and proprietary binaries are expressly excluded from this
source-only scope. The preflight does not infer rights to firmware from the
source lock or inventory. A source-only result also does not authorize a QEMU
binary, a bundled environment, or a release artifact: those require their own
dependency, patch, notice, and file-level review. M8-06 and M8-08 remain open
until the precise candidate files and release form have been reviewed and the
minimal verified baseline is ready.
