# Immutable source locks and cache

`upstreams.lock.yaml` is the reviewed source identity for diskOS, Disco!, QEMU and future community forks. It records canonical HTTPS GitHub repository URLs, full lowercase commit SHAs, source path projections, selected license-file SHA-256 checksums and provenance. See [the metadata review](UPSTREAM-PROVENANCE.md) for the initial pins and their review limits. A tag or branch in `provenance.reference` describes discovery only: synchronization uses the commit SHA.

The versioned `lab-upstreams/v1` contract is implemented by `source_lock.py` and published as [JSON Schema](../schemas/lab-upstreams-v1.schema.json). Unsupported versions, unknown keys, duplicate identifiers, floating revisions, credential-bearing URLs, non-GitHub URLs and unsafe paths are rejected. License metadata is scoped evidence, not a completed dependency/SPDX audit or a relicense of any component.

## Commands

Run from the Lab checkout after `uv sync --dev`:

```sh
uv run disc-lab sources list
uv run disc-lab sources sync
uv run disc-lab sources verify
uv run disc-lab sources sync --offline
uv run disc-lab sources verify --source diskos
```

`list` reads the lock and shows selected identities and cache locations without fetching or asserting cache validity. `sync` downloads missing source projections at their exact pins, verifies them before publication, and reuses existing entries only after verification. `verify` is offline and performs no repairs. `sync --offline` also requires valid existing entries and never fetches. Invalid input, missing/corrupt caches, unsafe paths and Git failures return exit 2 with diagnostics.

All commands accept `--lock FILE`, `--cache-dir RELATIVE/PATH` and `--source ID`. The default cache is `.lab/sources/` relative to the lock file's directory and is ignored by Git. Cache directory overrides must stay within that directory using a safe relative POSIX path. An alternate lock used outside this checkout needs an equivalent ignore rule; keep it out of published source.

## Source-only projections

The UI upstream trees contain flash helpers, prebuilt executables and other payloads. `includePaths` therefore explicitly locks the source files/directories to obtain. The initial UI projections include `ui/`, `docs/`, root `README.md` and `LICENSE`; QEMU includes selected code/documentation trees and excludes its firmware tooling tree. A trailing slash denotes a directory prefix; other entries denote exact files. Globs and traversal are not accepted. Selected license evidence must be included.

Synchronization uses Git's blobless partial fetch and a controlled source projection. Unselected blobs are intentionally absent. This is a verified **source projection**, not a full upstream checkout or proof that a UI can build. Selected symlinks and submodules are refused in M0; none occur in the initial selected pins. No Git LFS objects, release assets, firmware, installers or build recipes are fetched/executed recursively. New projections need metadata inspection before approval; selected paths must themselves contain source/redistributable assets suitable for the intended use. The manager cannot classify proprietary content from arbitrary filenames.

## Integrity and retention

Each cache entry is scoped by source identifier, exact commit and a digest of the sorted projection. Updating a pin or its projection produces a separate entry. Older entries remain available with the matching historical lock; there is no automatic garbage collection, reset, clean, pull or upgrade.

Verification checks repository ownership/layout, exact detached HEAD, locked remote, Git metadata/index state, materialized file set and committed bytes, and selected license hashes. Local changes, extra files, missing files, hidden index flags, unsafe links, mismatched identities or incomplete objects are refusals. Git hooks, user/system configuration, credential helpers and content filters are excluded from the managed Git operations. Cached files are for read-only consumers; future builds must use a separate workspace. Filesystem owners can still alter their files; verification is the integrity gate before use.

Existing invalid entries are preserved. Inspect them manually and select a separate clean cache if needed; `sync` will not repair or overwrite them. Temporary staging and exclusive per-entry synchronization markers live in the managed cache. On a failed operation the CLI reports the failure; interrupted staging/markers must be inspected before manual cleanup. Do not blindly remove directories based on an untrusted input path. No process should replace cache directories concurrently with a command; the local cache is not a hostile multi-user sandbox.

Publication uses an atomic no-replace rename on Windows and Linux (`renameat2` on Linux). Other hosts, or Linux systems without that operation, refuse new publication. Verification never enables Git transport protocols; sync enables HTTPS only for the explicit missing-source fetch/checkout stage and requires server partial-clone support. Git helpers have timeouts and never receive interactive credentials.

## Dependency upgrade procedure

1. Inspect the candidate upstream commit and tree metadata, including new binaries, submodules, symlinks, license declarations and relevant source changes. Do not run its scripts.
2. Resolve the chosen tag/branch to a full immutable commit, review the source projection, and record immutable provenance and raw license SHA-256 values.
3. Propose a lock-only/source-review update in a feature PR. Never rewrite the lock as a side effect of synchronization.
4. Sync the candidate into its separate entry; run offline verification and the firmware-free regression suite. Preserve previous pins/caches.
5. Review and promote explicitly. Source integrity never promotes firmware/UI/runtime compatibility. Runtime adapter and build acceptance belong to their later milestones.

Future GitHub forks use the same `SourcePin` contract and generic manager. Adding other hosting protocols, recursive dependencies or executable build adapters requires a separate reviewed change; no privileged special case exists for Sorane.
