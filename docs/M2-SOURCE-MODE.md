# M2-03 UI source mode foundation

This firmware-free foundation defines a strict source/build plan and offline
inspection API for external UI projects. The public plan contract is
[`lab-ui-source-mode/v1`](../schemas/lab-ui-source-mode-v1.schema.json), the
non-executed build record is
[`lab-ui-build-record/v1`](../schemas/lab-ui-build-record-v1.schema.json),
and inspection reports use
[`lab-ui-source-mode-report/v1`](../schemas/lab-ui-source-mode-report-v1.schema.json).
The Python models generate these checked-in schemas, and tests enforce parity.

## Source identities

A local plan names a `sourceId`, a provenance reference and review date, an
explicit file/directory projection, and the SHA-256 identity of the measured
projection manifest. `inspect_local_projection(root, projection)` computes
that identity without executing project files. `inspect_source_mode(plan,
local_root=...)` recomputes it and refuses changed or missing bytes. Directory
projections include every file beneath the selected directory; the manifest
records each relative path, byte count and SHA-256. Paths are relative POSIX
paths and reject traversal, Windows device names, alternate streams, links,
reparse points, special files and hard links. Inspection is capped at 10,000
files, 64 MiB per file, 512 MiB total and 15 seconds.

A Git plan names a canonical HTTPS GitHub `owner/repository.git` URL, a full
lowercase 40-character commit, source-lock ID and the projection-manifest
identity. The exact repository, commit and provenance must match one
`lab-upstreams/v1` source pin. The API calls `sources.verify_source` against
the existing cache; it makes no network request and does not implement a
second downloader. A commit string alone does not establish local bytes.

## Build plan and evidence

Plans carry a reviewed recipe identity and review reference, an expected
relative output path and SHA-256, and declared toolchain/build inputs with
version and digest. `reviewStatus: reviewed` is a caller declaration. It does
not authenticate a recipe or add it to a trusted execution registry. The
contract has no shell command field. The implementation does not run a recipe
or third-party build.

If the caller selects a build output root, the API checks every output path
component, requires a regular unlinked file, verifies its digest, and reuses
the M2-02 `preflight_ui_binary` path. The returned ELF status describes only
that existing static binary preflight. It never permits launch.

`validate_build_record` binds its accepted record to a canonical SHA-256 of
the complete plan, including source, provenance, recipe, declared build
inputs and output identity. Version 1 records require execution and
authentication to be `NOT RUN`, reproducibility to be `NOT MEASURED`, and
`launchAuthorized` to be false. These fields cannot be promoted by supplied
hashes or author claims. Reports distinguish inspected source bytes, verified
Git-cache commit binding, declared recipe review, output preflight state and
the gates that were not run.

Example local flow:

```python
from pathlib import Path

from snowsky_disc_lab.ui_source_mode import (
    inspect_local_projection,
    inspect_source_mode,
)

root = Path("/reviewed/local/ui")
projection = ["ui/"]
source_identity = inspect_local_projection(root, projection)
plan = {
    "apiVersion": "lab-ui-source-mode/v1",
    "kind": "UISourceModePlan",
    "source": {
        "mode": "local",
        "sourceId": "community-ui",
        "provenance": {
            "reference": "review:community-ui-source",
            "reviewedOn": "2026-10-22",
        },
        "projection": projection,
        "manifestSha256": source_identity["manifestSha256"],
    },
    "recipe": {
        "recipeId": "community-ui-build",
        "revision": "0123456789abcdef0123456789abcdef01234567",
        "reviewReference": "review:community-ui-build",
        "reviewStatus": "reviewed",
    },
    "inputs": [
        {
            "name": "mipsel-toolchain",
            "version": "reviewed-version",
            "sha256": "a" * 64,
        }
    ],
    "output": {"path": "out/ui.elf", "sha256": "b" * 64},
}
report = inspect_source_mode(plan, local_root=root)
```

The sample digest values above are placeholders and must be replaced by
reviewed identities. Filesystem inspection assumes a quiescent trusted local
owner; it refuses observed changes but is not a hostile-filesystem race
sandbox.

## Completed and deferred gates

Completed here: versioned strict plan, build-record and report contracts;
bounded local projection measurement; exact Git identity resolution through
the source lock and verified cache; expected output digest checking; reuse of
M2-02 ELF preflight; negative safety regressions; and explicit non-execution
evidence.

Deferred: an authenticated recipe registry, trusted recipe/toolchain review,
any build execution, measured reproducibility, signatures or other
authentication, dependency acquisition, capability assessment against trusted
runtime observations, UI launch authorization, M2 lifecycle/runtime work, and
all stock V2.57, IPC and physical-device acceptance. These remain `NOT RUN` or
unverified. Source-mode validation never authorizes UI launch.
