# M0 public data contracts

`schemas/lab-ui-v1.schema.json` and `schemas/lab-firmware-v1.schema.json` are generated from `snowsky_disc_lab.contracts`. Tests compare them to the models and validate the synthetic fixtures against JSON Schema. YAML is input data only: custom tags, duplicate keys, anchors/aliases, malformed UTF-8, oversized inputs and unknown fields fail closed. The input limit is 64 KiB; nesting is capped at 64 levels.

Only the exact `lab-ui/v1` and `lab-firmware/v1` API versions are accepted. Breaking changes require a new major contract; existing v1 fields will not silently change meaning or disappear. Future deprecation requires documentation and a migration example before removal. CLI 0.1 is experimental: the three implemented command paths and exit codes below are the M0 contract; future commands require their own review.

## UI manifests

Use [the synthetic UI example](../examples/ui-valid.yaml). Required fields describe identity, an immutable source revision, a preset identifier and output path, runtime constants and claimed firmware versions. Names are normalized to lowercase safe identifiers. Source revisions are full hexadecimal Git object identities. Presets `synthetic`, `diskos-musl` and `disco-musl` are recognized **data identifiers only**; no builder or reviewed executable recipe is shipped in M0. Approval for execution belongs to a future pinned recipe registry.

The target is `snowsky-disc`, architecture `mipsel`, display `[360, 360]`, and IPC `fiio-posix-mqueue`. These are declarations, not observations of an ELF binary. Firmware versions must be quoted YAML strings. Claims are never promoted to compatibility evidence.

`build.output` is a portable relative POSIX path, anchored to the manifest's directory. Absolute paths, drive/UNC paths, backslashes, traversal and unsafe components are refused. The loader resolves existing symlink parents and refuses escape from that directory. Outputs need not exist and are never opened or executed. JSON Schema covers lexical constraints; filesystem containment is an additional loader check. Future artifact access must recheck containment at use time to avoid races.

## Firmware profiles

Use [the synthetic firmware example](../examples/firmware-valid.yaml). Required identity includes `kind: Firmware`, `device: snowsky-disc`, and quoted `firmware.main` / `firmware.recovery`. Optional SHA-256 fields and runner references are future review data. Synthetic fixture hashes, if present, identify no vendor artifact. Passing this schema does not establish checksum equality, vendor origin, a reviewed runner or a usable runtime profile. No support-promotion field is accepted.

## CLI and trust boundaries

- `disc-lab doctor`: fixed host/version and cache metadata diagnostics, exit 0 when reporting completes. Missing dependencies are statuses, not exceptions. Default checks do not contact the Docker daemon. Explicit `--docker-daemon` queries its server version only and may contact a remote context. WSL distribution configuration and runtime compatibility remain unverified.
- `disc-lab ui validate FILE` and `disc-lab firmware validate FILE`: exit 0 on schema success, 2 on invalid data or IO failure. Diagnostics identify the field/error without printing manifest values or Python tracebacks.
- YAML cannot provide subprocess commands, environment settings, downloads or arbitrary build scripts. No code invokes a manifest field as a command.

Validation uses no temporary work directories and performs no artifact writes. uv/pytest use ignored local tooling directories. `.lab/`, caches, firmware, vendor inputs, working state and local evidence remain ignored. Do not put personal media or proprietary inputs elsewhere in the repository. Future extraction/cache workflows must define their own safe temporary directory ownership and cleanup policy before implementation.

This first-party implementation copies no upstream code or assets. M0-07's [initial inventory](LICENSE-INVENTORY.md) and [trust/versioning baseline](TRUST-BOUNDARIES.md) record known evidence and remaining distribution gates. The core LICENSE/NOTICE decision and complete relevant per-file clearance remain pending; this Draft implementation does not relicense third-party source or authorize firmware redistribution. No package publication or release workflow is included.

The separate `lab-upstreams/v1` lock contract and source cache commands are documented in [SOURCES.md](SOURCES.md). They reuse the bounded YAML loader while keeping source resolution independent of manifests and future emulator adapters.
