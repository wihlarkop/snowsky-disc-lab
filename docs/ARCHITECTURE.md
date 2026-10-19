# Architecture & UI Integration (proposed)

**State:** overall design specification. M0 implements CLI diagnostics, schema-only manifests and immutable source caching; [CONTRACTS.md](CONTRACTS.md), [SOURCES.md](SOURCES.md) and the published JSON schemas define the executable contracts. Remaining interfaces, runtime commands, directories and illustrative YAML below are proposals.

## 1. Scope, product boundaries

The goal is one **DISC-focused** emulator/dev workflow that accepts third-party UI binaries or source projects, including diskOS, diskOS Disco! and a separate Sorane project. It is **not** a monolithic fork of all upstream sources, nor a full-system Ingenic X2000 simulator.

```text
                      Git repo / local binary
                    +--------------------------+
                    | diskOS  Disco!  Sorane   |
                    | independent community UI |
                    +-------------+------------+
                                  |
                          Lab UI contract v1
                                  |
          +-----------------------v-----------------------+
          |               snowsky-disc-lab               |
          | CLI/API, manifest validation, lock resolution |
          | build orchestrator, verified adapter registry |
          | test harness, compatibility evidence store   |
          +------------+-------------------+-------------+
                       |                   |
            pinned QEMU runner      firmware registry
                       |                   |
                       +---------+---------+
                                 |
                 isolated validated FiiO rootfs
                    stock mq_player + device shims
                                 |
               framebuffer / input / IPC / PCM / logs
                                 |
                        viewer + reports
```

The *separate Sorane repository* owns its UI source, screens, theme work, artwork rights, build recipe and release process. It must not have privileged imports or undocumented launch flags unavailable to other UI developers. Do not create/link a Sorane GitHub repo until one actually exists.

## 2. Ownership and upstream policy

| Component | Home | Ownership / update policy |
| --- | --- | --- |
| UI/firmware schemas, CLI, orchestrator | Lab | First-party; public versioned contract |
| Integration scripts, QEMU adapters, compatibility records | Lab | First-party narrow code; versioned and tested |
| diskOS installer/UI source | b0hemia/diskos | Immutable checkout from upstream; no wholesale copying |
| Disco! source/theme framework | zmd22/diskos-disco | Immutable checkout from upstream; no wholesale copying |
| QEMU runtime/shims/viewer | eudj1n/snowsky-disc-qemu | Immutable checkout from upstream; prefer external overlays; explicit review for patches |
| User-selected firmware rootfs/stock `mq_player` | Locally supplied official FiiO package | Never a Git tracked dependency or public artifact |
| Sorane custom UI | Separate GitHub repository (not created yet) | Its own release/issue history and GPL obligations if derivative |

Target directory arrangement (implementation not started):

```text
snowsky-disc-lab/
├── README.md
├── CONTRIBUTING.md
├── docs/
│   ├── ROADMAP.md
│   ├── ARCHITECTURE.md
│   └── COMPATIBILITY.md
├── lab/                      # package under discussion
│   ├── cli/
│   ├── sources/
│   ├── firmware/
│   ├── adapters/
│   ├── runtime/
│   ├── evidence/
│   └── security/
├── schemas/
│   ├── lab-ui-v1.schema.json
│   └── lab-firmware-v1.schema.json
├── presets/
│   ├── diskos.yaml
│   └── disco.yaml
├── profiles/                 # curated and independently reviewed
├── tests/
│   ├── contracts/
│   ├── synthetic/
│   └── integration/
├── examples/
│   └── hello-disc-ui/
├── upstreams.lock.yaml       # exact immutable refs/hashes
└── .gitignore                # vendor/firmware/binaries/cache
```

Nontracked user cache (example, not committed):

```text
<user cache root>/
├── source/<repo>/<commit>/
├── firmware/<product>/<version>/<rootfs_sha256>/
├── runners/<qemu_commit>/
├── work/<firmware_hash>/<ui_hash>/<run-id>/
└── evidence/local/<run-id>/
```

The M0 source resolver uses immutable lock entries and separate cached projections, with Git blobless fetches and explicitly selected paths. This supports future UI forks through the same contract and avoids downloading upstream flash payloads or recursively resolving submodules. Cache identity includes commit and projection; build/runtime adapters must consume verified sources read-only and use separate working state. See [the implementation decision and upgrade procedure](SOURCES.md). No upstream code is vendored into the Lab tree.

## 3. Artifact flow and execution boundaries

**Firmware input**
1. User provides an official firmware ZIP, vetted OTA folder or a previously verified local extraction.
2. Validate file names, maximum sizes, exact expected vendor metadata, contiguous chunks and assembled rootfs hash before extraction.
3. Check approved firmware profile and the exact identity/ELF SHA-256. Missing or different = `unknown`; do not repurpose a similar version's patch addresses.
4. Extract to fresh isolated local storage with no network publication; never upload rootfs or stock MIPS binaries as CI artifacts.

**UI input**
1. A local binary or a repository at an immutable Git commit is supplied.
2. Parse versioned UI manifest and inspect artifact architecture/ABI and dependencies.
3. For source input, run *only a reviewed, appropriately isolated build preset*. The manifest must not be treated as a trusted shell script.
4. Preserve a signed or SHA-256 recorded binary/build provenance chain; version naming is not a substitute for hashes.
5. Submit the built or supplied `mq_ui` to the runtime adapter only after runtime preflight.

**Emulated runtime**
1. Pick the specific reviewed firmware profile and compatible **pinned runner**, never implicitly the most recent.
2. Start isolated guest state, checked stock `mq_player`, audio device shims, framebuffer/touch input adapters and allowed virtual SD fixtures.
3. Inject UI through a narrowly defined, version-appropriate handoff. The current upstream [historical diskOS preview](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/experiments/diskos/docs/preview.md) used a *warm-player* handoff plus framebuffer `ioctl` adapter; it is **not** a reusable generic solution without fresh testing.
4. Collect frame states, crash/stdout/stderr, IPC health and sample-validated PCM for applicable scenarios.
5. Stop guest processes and retain only safe local evidence; restore no shared mutable volume implicitly.

**Report**
- Record the complete tuple `device + firmware(main/recovery/rootfs/stock player hash) + qemu runner + UI artifact + adapter + test suite + host`.
- Emit per-scenario results with explicit `NOT RUN`, `UNSUPPORTED` and reproducible supporting artifacts.
- No emulator-only evidence may become a physical-device certification.

## 4. External UI contract proposal: `lab-ui/v1`

A manifest is optional for **binary inspection mode** but required for automation of **source builds**. Draft example:

```yaml
# snowsky-lab.yaml — DESIGN ONLY, not implemented
apiVersion: lab-ui/v1
kind: UI
metadata:
  name: example-fork
  upstream: https://github.com/example/fork
source:
  revision: "FULL_GIT_COMMIT_SHA" # immutable
build:
  preset: diskos-musl          # known/pinned recipe, not arbitrary host shell
  output: ui/mq_ui
runtime:
  target: snowsky-disc
  architecture: mipsel
  display: [360, 360]
  ipc: fiio-posix-mqueue
  launchProfile: auto          # adapter resolves only reviewed choices
claims:
  firmware: ["2.57"]          # contributor claim, NOT a Lab verification
tests:
  suites: ["ui-smoke"]
```

Contract requirements:

- `apiVersion` selects a validated schema and compatibility behavior; unknown major versions fail.
- `metadata.name` is a safe canonical identifier, **not** a shell fragment or executable path.
- Source must be immutable for reproduction; a branch name may be used only as a discovery input before resolving/pinning a commit.
- File paths must remain in a sandbox workspace; reject path traversal, symlink escapes and unexpected absolute outputs.
- A recipe preset is mapped to a Lab-reviewed builder/toolchain. Advanced custom build steps may be supported later behind a separate explicit trust and isolation decision.
- A UI's claimed firmware list is advisory until independent Lab testing passes.
- Binary inspection checks MIPS endianness, ELF load type, float ABI, necessary libs and device syscall assumptions; some ABI properties need target-hardware acceptance.
- The contract does not authorize access to the user's host, network, USB devices, signing keys or firmware archive.

### Adapter interface v1 (behavioral)

| Operation | Inputs | Output / refusal |
| --- | --- | --- |
| `inspect` | source manifest or `mq_ui` path | artifact identity, ABI report, dependencies |
| `build` | immutable source + trusted preset | compiled output, build provenance, logs |
| `preflight` | firmware profile + UI artifact + runner | reviewed capability/launch contract or explicit refusal |
| `launch` | isolated guest state + validated tuple | UI PID/health + frame readiness |
| `stop` | run ID | confined UI shutdown with collected exit reason |
| `collect` | run ID | frames, logs, PCM, test observations |
| `report` | evidence set | versioned machine/human reports |

Adapters may declare different framebuffer/handoff requirements without exporting an arbitrary code execution interface. The first externally authored example UI should function without any source changes to core adapter logic.

## 5. Stable vs changing surfaces

**Stable public APIs (goal)**:
- manifest/schema validation, local binary input, build presets, `run`, `test`, report schema, per-scenario status semantics.

**Intentionally internal / revision-gated**:
- QEMU patched `ioctl` routes, stock `mq_player` addresses, rootfs paths, `/proc` probes, start/warm handoff and FiiO protocol workarounds.

**Never promoted from an unknown firmware**:
- raw memory addresses, per-build patch locations or callback offsets;
- unsupported operations inferred from a later version number;
- undocumented network behavior.

The Lab should offer multiple retained runner snapshots if upstream changes break old profiles; a single *public CLI* does not imply one QEMU binary must support every version.

## 6. Reproducibility / upstream update handling

An `upstreams.lock.yaml` entry (draft) should resolve each selected public repo to:

- canonical Git URL, full commit SHA, tag for display only, optionally signed release assets + checksums;
- build preset version and toolchain digest;
- patch-set ID + reviewed source/target checksums;
- compatible adapter schema versions;
- license notice references.

Updates create a **candidate**; they do not mutate pinned accepted revisions. Run source-only smoke tests, trusted firmware integration for affected combos, compare evidence, review and then promote. Old runners and verified evidence remain addressable.

## 7. Host and security boundaries

Upstream QEMU currently requires modern Docker Engine/Compose and uses Linux container machinery; the proposed Windows host route is **WSL2 + Docker**, a requirement to validate, not an already supported Lab configuration.

```text
UNTRUSTED (PRs/community code)              TRUSTED/OPT-IN (local)
----------------------------------           ---------------------------------
schema, lint, static ELF inspection           verified official FiiO firmware
mock mqueue + host-render tests               approved pinned QEMU guest
nonprivileged reproducible UI build           opt-in external UI guest execution
NO privileged Docker, NO secrets              isolated guest state and local logs
NO USB/firmware/decrypted binaries            no host USB / device flashing
```

**Important limitation:** qemu-user runs atop the Docker VM/host kernel; a container is not a perfect security boundary. Never execute arbitrary unreviewed fork binaries against a privileged runtime merely because a schema passes. CI for untrusted forks must not run firmware-backed privileged containers. Prefer reviewed patches, restricted host/network mounts, local opt-in and dedicated isolation for trusted integration.

Host mounts default read-only where possible; test reports may only publish **allowlisted** nonproprietary artifacts after review. Secrets and firmware paths must be redacted.

## 8. Licensing boundaries

- [snowsky-disc-qemu LICENSE](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/LICENSE): MIT.
- [diskOS UI](https://github.com/b0hemia/diskos/blob/main/ui/README.md): GPL-3.0-or-later; upstream installer/tooling has separately identified MIT licensing.
- [Disco! UI](https://github.com/zmd22/diskos-disco/blob/main/ui/README.md): GPL-3.0-or-later; repo tooling and docs may have different terms.

The Lab *intends* permissive licensing only for its original standalone glue code; do not label third-party or GPL derivative code as MIT. A final LICENSE/NOTICE strategy and per-file audit are required before shipping code. Sorane stays outside this repository and follows its own derivative UI license obligations. Do not redistribute custom firmware images containing FiiO rootfs.

## 9. Architecture decision records to make during M0–M2

- **ADR-001:** Python CLI vs other implementation language, packaging and Windows support.
- **ADR-002:** checked-out cached upstream lock vs submodules for baseline QEMU; isolation of arbitrary UI forks.
- **ADR-003:** schema and semver support guarantees for `lab-ui/v1`.
- **ADR-004:** two-stage untrusted build vs trusted QEMU runtime execution/security.
- **ADR-005:** guest handoff semantics (cold init / warm handoff) and stock `mq_player` lifecycle.
- **ADR-006:** per-firmware runner/overlay selection, retention, and stale/unsupported states.
- **ADR-007:** evidence schema, screenshot baselines, privacy/retention and release publishing.

See [the roadmap](ROADMAP.md) for implementation priority and [compatibility policy](COMPATIBILITY.md) for promotion gates.
