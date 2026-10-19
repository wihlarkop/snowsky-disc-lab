# M0 trust and execution boundaries

This is the required baseline for designing M1. It documents enforced M0 behavior and the gates that later execution code must implement. It does not authorize firmware acquisition, builds, privileged containers, device access, or runtime execution. A passed doctor or source check never grants those permissions.

## Trust domains

| Domain | M0 authority and permitted behavior | Boundary before later execution |
| --- | --- | --- |
| Reviewed Lab core | Parses bounded data, invokes fixed diagnostic/Git commands, verifies pinned source projections. Code changes require review and firmware-free regression checks. | Core is trusted for orchestration; it does not make fetched code trusted. |
| Community repositories and manifests | Untrusted data even when an exact commit and checksum match. Source pinning establishes identity; claims remain claims. | Never invoke source-provided hooks, shell fields, installers, tests or recipes during sync/validation. Review any future builder separately. |
| Source cache | Exact commit/projection identity, controlled Git metadata, verified blobs and license checks, read-only source files. Existing invalid entries are refused and preserved. | Consume verified sources through a separate build workspace. Do not grant cached code firmware, secrets, devices or privileged runtime access. |
| Nonprivileged source build (future) | Not implemented. | A reviewed pinned recipe in a separate unprivileged environment, no host sockets/USB, no firmware/secrets, bounded outputs. Dependency network access must be separately declared. Successful build does not authorize execution. |
| Trusted QEMU integration (future) | Not implemented. | Maintainer-reviewed core/adapter and exact source/artifact pins, user-supplied lawful firmware, explicit local authorization, dedicated state, restricted mounts/network and reviewed privilege needs. Do not assume Docker or qemu-user is a security sandbox. |
| Proprietary firmware (future) | No intake, extraction or execution in M0. | Local ignored/private storage; exact inventory/hash checks and reviewed signature coverage before executable use. No rootfs, vendor binaries, keys or device dumps in Git, CI or shared reports. Unknown firmware fails closed. |

The reviewed core and generated test fixtures are the only code exercised by public CI. The workflow has read-only repository permission, no persisted checkout credentials, no shared dependency cache, no firmware, no USB, no Docker socket, no privileged runner and no secrets. Synthetic Git fixtures test synchronization without fetching/executing external code. Do not use `pull_request_target` to run untrusted branch code with maintainer privileges. Future trusted firmware acceptance must be a separate reviewed local workflow, with no automatic escalation from PR results.

## What M0 enforces

- YAML is a bounded regular-file read, with strict versioned models, forbidden extra keys, no custom constructors, duplicate keys, anchors or aliases. Manifest values are never subprocess commands.
- Source URLs are canonical HTTPS GitHub URLs without credentials, options, local paths or redirects. Network sync requests immutable commits and source-only projections. Offline operations disable Git transport protocols. Git system/user config, hooks, credential helpers, filters and replacement/alternate object stores cannot silently redefine the managed operation.
- Cache paths retain commit/projection identity. Portable paths, containment, symlink/junction and special-file checks protect the existing private-cache contract. Selected symlinks/submodules are unsupported. Publication refuses replacement on supported Windows/Linux hosts. These checks are not protection against a hostile filesystem owner swapping paths concurrently.
- Default doctor uses fixed version queries and filesystem metadata. It does not contact Docker's daemon, enumerate devices, start a WSL distribution, perform write probes or configure services. Optional daemon contact requires `--docker-daemon` and may reach a configured remote context; it remains a diagnostic, with no container creation/start.
- No M0 command builds an upstream project, downloads firmware, extracts an archive, launches QEMU, writes USB, flashes a device, or publishes artifacts.

## Temporary state, ownership and cleanup

Source sync creates private staging under the selected source cache, takes an exclusive per-entry marker under `.locks/`, verifies before atomic no-replace publication, and removes its own normal-completion lock marker. Successful source entries are retained indefinitely until a separately reviewed retention feature exists. Changed pins/projections get different entries; no automatic rollback or deletion of old snapshots occurs.

Failed staging is retained and identified in the diagnostic. An interrupted process may leave a marker; `sync` refuses to bypass it. A PID alone is not evidence that a marker is stale: inspect the exact operation, host and relevant process state first. Corrupt final entries are never reset, repaired or replaced. Select a different clean cache for recovery if needed.

There is deliberately no general recursive cleanup command. Before any **manual** removal, verify the literal resolved target is the intended generated staging/marker within the expected cache, is not the cache root, a completed entry, repository, firmware store, symlink, junction or mount redirection, and has no active owner. Preserve useful nonproprietary failure evidence first. Remove only that exact owned target using the native shell; do not derive deletion commands from manifests, Git output or wildcard matches. These are cleanup preconditions, not a request to delete current state.

Future automated cleanup must have explicit ownership metadata, a confinement check at use time, no-follow traversal, concurrency protection and tests for interrupted/racing operations before adoption. Retention/deletion of proprietary firmware requires its own explicit user policy; a source-cache cleanup policy cannot cover it.

Tests own `.pytest-tmp/`; pytest may replace only that generated scratch directory. uv and lint caches are ignored local tool state. Doctor creates none of these paths. Source synchronization is the only current product command that creates a managed source cache. Other ignored local state stays private.

## Artifact publication and attribution

Public output is opt-in and allowlisted by artifact type and exact path after review. Candidate shareable data includes sanitized test outcomes, immutable public source IDs, selected license notices and generated synthetic screenshots/audio. Logs and diagnostics can contain usernames/local paths; inspect before posting. No automatic upload/export command exists.

Reject vendor archives/rootfs/binaries, memory/device dumps, personal music or artwork, signing material, credentials, credential-bearing URLs and unreviewed logs. Never publish an entire work/cache/firmware directory. Hash equality is evidence of matching bytes, not vendor authenticity, a license grant or runtime compatibility. Future report generation must validate containment again when opening artifacts and refuse unsafe links.

Preserve upstream notices in external source projections and future corresponding-source distributions. Review each included component's own declaration, license and assets; the root MIT notice does not relicense GPL UI, vendored libraries or fonts. The initial [license inventory](LICENSE-INVENTORY.md) and its evidence identify both known boundaries and unresolved redistribution gates. No Lab LICENSE is chosen or upstream license changed by this milestone. Core licensing and any pending component evidence must be resolved by the owner before a packaged/public release that depends on them.

## Versioning and compatibility guarantees

`lab-ui/v1`, `lab-firmware/v1` and `lab-upstreams/v1` select exact major contracts. Unknown versions and unsupported fields fail closed. Breaking meaning/required-field changes require a new major version, explicit migration guidance and retained old-version interpretation; do not silently reinterpret old accepted profiles or pins. Additive changes require tests proving previously valid documented data retains its meaning. Announce deprecation and its migration before removal; there is no automatic conversion or network update.

The CLI package is experimental `0.1.x`. Existing `doctor`, manifest validation and `sources list|sync|verify` paths retain their semantics. Doctor returns 0 when reporting finishes even with unavailable/warning/not-verified checks; malformed CLI/path input returns 2. Validators/source operations return 0 on the scoped check's success and 2 on refusal/IO failure. New diagnostic rows and human-readable wording may change; terminal tables are not a machine-stable API. No JSON doctor API is promised. Python helper functions and cache internals remain internal; preserving current cache compatibility requires a migration/retention design before changing their layout.

Source pin/projection format, URL and hash validation, snapshot identity and source-state refusal rules remain unchanged by host diagnostics. Doctor reports a location and metadata only: use `sources verify` for cache integrity. `AVAILABLE` means the named observation succeeded, `UNAVAILABLE` means a required observation/tool failed or is absent, `WARNING` identifies a limitation or suspicious condition, and `NOT VERIFIED` means the claimed property was not measured. None may be promoted to emulator/device support.

## Gates before M1 execution

1. Review and integrate the stacked M0 PRs and obtain firmware-free CI evidence on the exact integrated head. Local green tests are distinct from hosted/other-platform success.
2. Review M0-08's [external-UI handoff ADR](adr/0001-external-ui-handoff.md): stock player ownership/startup order, cold-first sessions, deferred warm handoff, immutable binary/patch anchors, private IPC/framebuffer paths and bounded stop/failure behavior. This design deliverable is not permission to implement or execute a UI launcher.
3. Before adding intake/runtime code, review exact M1 runner/toolchain/container pins, local firmware identity/authenticity checks, isolation/mount/network decisions, temporary-state ownership and export allowlists. Keep host readiness, source integrity and firmware/runtime compatibility separate.
4. Close license/attribution unknowns for the precise code/assets to be built or redistributed. Initial inventory does not clear every file or authorize bundling the vendor image. Resolve Lab core licensing before its packaged release.

M0's scoped deliverables, including the proposed handoff ADR, are ready for review; [stacked integration and exact integrated-head CI](M0-INTEGRATION-READINESS.md) still gate closure. Platform runtime evidence and relevant build/distribution clearance remain later execution/release gates. No compatibility state is promoted by this document.
