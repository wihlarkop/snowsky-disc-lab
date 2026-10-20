# SNOWSKY DISC Lab

**A proposed community development, emulation, and compatibility lab for the FiiO / SNOWSKY DISC.**

> **Project status: M0 foundation with partial M1 intake/workspace preparation and firmware-free synthetic execution.** The CLI provides host diagnostics, strict UI/firmware manifest validation, immutable upstream source projections, bounded local candidate inspection and private snapshot preparation. A [fixed synthetic runtime](docs/synthetic-runtime.md) reuses the pinned QEMU build to exercise filesystem and session isolation. Firmware extraction/execution, adapter SDK and device flashing are not implemented. No firmware/UI combination is Lab-verified. Commands in the planned experience section remain design targets.

[M1-01 runtime preparation](docs/M1-01-RUNTIME-PREPARATION.md) records reviewed stock V2.57 source/build inputs, local firmware identity requirements and isolation boundaries. Firmware-backed execution gates remain open; no prebuilt runtime runner is shipped.

[M1-02 firmware intake](docs/FIRMWARE-INTAKE.md) adds offline, read-only `disc-lab firmware inspect PATH --format text|json` for local ZIP/package candidates. Structural acceptance grants no authenticity, compatibility, extraction or execution authority. Only synthetic inputs have been verified.

[M1-03 workspace preparation](docs/FIRMWARE-INTAKE.md#m1-03--private-workspace-preparation) adds per-session local snapshots, integrity rechecks, quotas, atomic publication and retained quarantine. It does not extract firmware. Workspace receipts keep extraction/execution authority false, and no real FiiO firmware has been used.

SNOWSKY DISC Lab aims to provide one reproducible workflow for:

- Running **stock DISC firmware** in an isolated QEMU-based development environment.
- Building and previewing UI implementations from **diskOS**, **diskOS Disco!**, **Sorane**, and independent community forks.
- Supporting **multiple firmware revisions concurrently**, retaining previously validated combinations when upstream projects update.
- Producing evidence-based **firmware × UI × adapter × emulator** compatibility reports.
- Detecting new FiiO and UI releases **without automatically trusting, executing, or promoting** them.
- Testing UI behavior, screenshot output, input, IPC, and audio in the emulator before optional testing on a physical DISC.

The initial and only committed device scope is **SNOWSKY DISC (Ingenic X2000)**. Other devices such as SNOWSKY Echo are **out of scope**; reusable code may be extracted later if real hardware and firmware research justifies it.

## Start here

| Document | Purpose |
| --- | --- |
| [Detailed roadmap](docs/ROADMAP.md) | Milestones, task breakdown, acceptance criteria, dependencies, risks and priorities |
| [Architecture & UI integration](docs/ARCHITECTURE.md) | Dependency strategy, adapters, plugin manifest proposal, CLI and trust boundaries |
| [External UI handoff ADR](docs/adr/0001-external-ui-handoff.md) | Pinned historical evidence, cold-first lifecycle and M1/M2 boundaries |
| [M0 integration readiness](docs/M0-INTEGRATION-READINESS.md) | Stack order, verification evidence, closure and release gates |
| [Final M0 integration candidate](docs/M0-FINAL-INTEGRATION.md) | Latest-main preservation, combined-tree verification and recommended merge strategy |
| [Compatibility & validation policy](docs/COMPATIBILITY.md) | Firmware profiles, support states, CI matrix, OTA intake and evidence rules |
| [Firmware update manager](docs/UPDATE_MANAGER.md) | FiiO OTA detection, registered UI fork compatibility checks and safe separate update channels |
| [Contributing](CONTRIBUTING.md) | How community developers can eventually add UI forks, firmware evidence and emulator fixes |
| [Technology stack](docs/TECH_STACK.md) | Python 3.12+, uv, Ruff, Astral ty, QEMU/C, LVGL and future Svelte Developer Studio |

## Upstream projects

| Upstream | Role |
| --- | --- |
| [b0hemia/diskos](https://github.com/b0hemia/diskos) | Custom LVGL `mq_ui`, stock player integration, build and on-device installation research |
| [zmd22/diskos-disco](https://github.com/zmd22/diskos-disco) | Extended UI/theme framework, signed SD-update workflow, additional user-facing features |
| [eudj1n/snowsky-disc-qemu](https://github.com/eudj1n/snowsky-disc-qemu) | QEMU user-mode runtime, firmware profiles, emulated device interfaces, browser viewer and integration checks |

**Ownership boundary:** we will not paste all three upstream codebases into this repository. The design is to resolve **immutable, reviewed upstream revisions** into an ignored local cache, add a narrow integration/adapter layer here, and propose broadly useful changes upstream. If a patch is required, it must be version-pinned and verified. All licenses and attributions remain in force.

### Separate UI product: Sorane

**Sorane** is the working name of our own custom DISC interface, planned as a **separate repository**. It should consume the same public integration contract as any community fork—no private emulator shortcuts. A future Sorane repository link will be added only after that repository exists. If based on diskOS/Disco! UI sources, its redistribution must respect **GPL-3.0-or-later** and third-party asset licenses.

## What is supported today?

**No firmware/runtime combination has been validated by SNOWSKY DISC Lab yet.** The table summarizes *upstream evidence as of 2026-10-19* to determine initial work, not a promise about our runtime.

| FiiO stock firmware | diskOS 1.2.1 installer | Disco! 2.5.6 | Upstream QEMU stock runtime | Lab validation |
| --- | --- | --- | --- | --- |
| V2.09 | Listed by diskOS | Not an officially supported Disco! base | No reviewed profile | Not run |
| V2.28 | Listed by diskOS | Not an officially supported Disco! base | No reviewed profile | Not run |
| V2.40 | Listed by diskOS | Not an officially supported Disco! base | Historical profile / preview experiment | Not run |
| V2.57 | Listed by diskOS | Supported base per Disco! documentation | Active reviewed firmware | Not run |
| Newer / unknown | Unknown until reviewed | Unknown until reviewed | Unknown until ported | Not run |

Upstream details: [diskOS install](https://github.com/b0hemia/diskos/blob/main/docs/INSTALL.md), [Disco! README](https://github.com/zmd22/diskos-disco), [QEMU firmware profiles](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/firmware/docs/firmware-profiles.md), [QEMU limits](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/emulator/docs/limits.md).

## Runnable M0 CLI

Install Python 3.12+ and [uv](https://docs.astral.sh/uv/), then from a clean clone:

```sh
uv sync --locked --dev
uv run disc-lab --help
uv run disc-lab doctor
uv run disc-lab ui validate examples/ui-valid.yaml
uv run disc-lab firmware validate examples/firmware-valid.yaml
uv run disc-lab sources list
```

`doctor` reports host/architecture, Python/Git/uv, Docker/Compose versions, WSL evidence, source-cache location, disk space and permission/path warnings. Default behavior is read-only and does not contact the daemon/network, start/configure services or distributions, probe devices, download or write files. Missing tools and limited evidence produce actionable `UNAVAILABLE`, `WARNING` or `NOT VERIFIED` rows; a completed diagnostic returns 0. An explicit `--docker-daemon` permits a fixed server-version query against the configured context, which may be remote. Neither mode proves WSL2/Docker/QEMU runtime compatibility. See [host preflight](docs/HOST-PREFLIGHT.md).

Validation reads YAML only. Exit 0 means the **schema passed**, never binary compatibility, vendor authenticity or firmware support. Invalid input, missing files and unsupported API versions return 2. See [public contracts](docs/CONTRACTS.md), [JSON schemas](schemas/) and [verification scope](docs/M0-VERIFICATION.md).

```sh
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run pytest
```

The lockfile pins application and development dependencies. The isolated Hatchling build backend currently has a lower-bound requirement in `pyproject.toml`, not an exact lock; reproducible packaged builds need a separate release pin/review. Firmware-free CI checks Linux and Windows on Python 3.12 and 3.14 without secrets, firmware, privileged containers or devices. Core M0 host targets are native Linux and Windows Python; WSL2/Docker emulator integration is pending M1 validation. Other hosts are unverified.

With Git installed, synchronize the reviewed source projections separately:

```sh
uv run disc-lab sources sync
uv run disc-lab sources verify
uv run disc-lab sources sync --offline
```

[`upstreams.lock.yaml`](upstreams.lock.yaml) selects exact commits and source-only paths. The ignored `.lab/sources/` cache retains previous revisions; changed/corrupt entries are refused and preserved. `verify` and `sync --offline` never fetch. Flash payloads tracked by upstream repositories are excluded. See [source management and upgrades](docs/SOURCES.md) and [pin provenance](docs/UPSTREAM-PROVENANCE.md). Source verification establishes source identity only.

## Planned developer experience (not implemented)

```sh
disc-lab firmware inventory --version 2.57 --archive /path/to/official.zip
disc-lab ui build --source /path/to/my-ui --ref <immutable-commit>
disc-lab run --firmware 2.57 --ui /path/to/mq_ui
disc-lab test --firmware 2.57 --ui /path/to/mq_ui --suite ui-smoke
disc-lab compatibility report
```

External Git sources will require an explicit immutable ref, safe checkout, reviewable build recipe, and appropriate trust separation. Local binaries can be inspected without executing them first.

**Test policy:** no TDD, no mandatory unit-test suite or coverage targets. Prioritize real CLI integration/contract checks and emulator regression tests when available.

## Non-goals and safety

- **Not** a full-system, cycle-accurate, NAND/USB/Bluetooth/real-DAC hardware emulator. Current upstream uses **QEMU user mode** and substitutes many interfaces.
- **Not** a promise that any binary or UI fork will boot with every firmware.
- **Not** a firmware redistributor. Do **not** commit vendor ZIPs, decrypted rootfs, stock executables, generated firmware images, signing private keys, device data or secrets.
- **Not** an automated flasher. No background or CI process may write to a real DISC. Hardware deployment, if added, requires a separate explicit approval, validated prerequisites, recoverability plan and physical-device testing.
- **Not** permission to execute untrusted third-party builds inside a privileged firmware/QEMU environment. Public PR checks must not be given proprietary firmware, secrets or host device access.
- **Not** a replacement for physical performance measurements. QEMU responsiveness, CPU and memory metrics do not establish X2000 timing, battery use, or real-device frame rate.

**Trademark notice:** this is an independent community project and is not affiliated with FiiO, SNOWSKY, Ingenic, or the upstream maintainers.

## Immediate next step

Review the [final M0 integration candidate](docs/M0-FINAL-INTEGRATION.md), which combines PR #2 → #3 → #4 → #5 with newer main decisions. Close M0 only after approval, integration and successful CI for the exact combined tree; the original PRs remain untouched. The first M1 task is **M1-01: pinned stock V2.57 QEMU runtime preparation**, followed by lawful local firmware intake and stock acceptance before custom UI execution in M2 under the [handoff ADR](docs/adr/0001-external-ui-handoff.md). The [trust baseline](docs/TRUST-BOUNDARIES.md) and [initial license inventory](docs/LICENSE-INVENTORY.md) keep unresolved build/distribution rights explicit; the Lab's root license is still unset. Older versions and warm UI replacement require separate reviewed evidence.
