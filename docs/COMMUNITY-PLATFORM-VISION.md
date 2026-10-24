# Community development platform and update center — future product direction

**Status:** proposal/backlog only, recorded 2026-10-25. **No new CLI, runtime, SDK, update mechanism, firmware acceptance, installation ability or device support is implemented by this document.** The existing M1 stock V2.57 QEMU reproducibility gate remains the critical path. See [roadmap](ROADMAP.md), [update manager](UPDATE_MANAGER.md), [compatibility policy](COMPATIBILITY.md) and [trust boundaries](TRUST-BOUNDARIES.md).

## 1. Product intent

SNOWSKY DISC Lab is intended to become the **Snowsky DISC development, experimentation, testing, cross-community compatibility and optional update hub**. It is **not merely a diskOS/Disco! installer or a single-UI emulator**.

The long-term experience should let independent authors:

1. **Create and test entire UIs** (diskOS, Disco!, Sorane and unrelated community forks) using one public, documented external UI contract.
2. **Extend a UI with features and apps**: custom screens, themes, visualizers, library utilities, playback controls, networking, audio-output features and optional local companion services.
3. **Experiment with stock capabilities** through responsibly reviewed IPC/device interfaces, supported mocks, static analysis and opt-in controlled runtime tests.
4. **Compare compatibility across community projects** and multiple stock firmware versions, including individual capabilities, dependencies, extensions and regressions.
5. **Discover, review and prepare updates from one place** for Lab components, community UIs, UI extensions and supported device UI-only update paths, without depending on a new universal flasher.
6. **Keep experimentation separate from device risk**: firmware-free development by default; firmware-backed execution and physical deployment gated separately.

The common developer path is **fork or create → declare requirements → preview/mock → build/preflight → approved QEMU scenarios → compatibility report → optional authorized device validation → prepare approved update**. An upstream release or host-render success is not a Lab runtime/device PASS.

## 2. Three artifact classes, not a fictitious universal plugin ABI

| Candidate artifact kind | Examples | Initial integration model | Compatibility implication |
| --- | --- | --- | --- |
| `full-ui` | diskOS, Disco!, Sorane, custom `mq_ui` | Reviewed source preset or exact local ELF; substitute the UI in a supervised stock-player session after M1/M2 acceptance | Tied to firmware/player ABI, runner, UI source/ELF and exact scenarios |
| `ui-extension` | Additional theme, screen, visualizer, app view | **Source-integrated** module or documented host-specific extension point initially; only claim dynamic plugins if a concrete UI host implements and validates an ABI | Must identify the supporting UI host, extension API/ABI version and build output; no promise that an extension loads unchanged on every UI |
| `service-app` | Network radio, AirPlay sender, metadata/utility helper | Separate supervised executable/service plus explicitly designed UI integration where supported | Track network, filesystem, process, PCM, privileges, resource and lifecycle requirements; unsupported guest/hardware functions must be declared |

A later shared extension SDK may supply versioned **capability interfaces** (display/UI events, music metadata, queues/transport, local storage, network, audio routing, lifecycle). It must not silently promise stable ABI compatibility with existing diskOS/Disco!/stock binaries. Project owners need to opt in to common integration contracts or use narrowly reviewed adapters.

For example, **AirPlay Receiving** may use independently confirmed stock `mq_player` interfaces on a supported firmware, whereas **Google Cast and AirPlay Sending** may require additional discovery, crypto, network, decoding and routing implementations. A hypothetical **Spotify** feature needs independent licensing/terms, authorization, codec, network and hardware-feasibility review; the Lab should enable safe development experiments, not promise officially supported Spotify playback or distribute unauthorized clients.

## 3. Developer kit, reverse engineering and evidence

Future author-facing capabilities:

- Firmware-free LVGL host render, synthetic music/media catalog, input/touch/key simulation, POSIX mqueue/player mocks, deterministic screenshot and PCM fixtures.
- Versioned, least-privilege capability manifest for firmware requirements, dependencies, network endpoints/credentials, user storage, audio sinks, subprocesses and hardware-only operations.
- Offline contract and ABI preflight with actionable `UNSUPPORTED`, `BLOCKED`, `NOT RUN` and `FAIL`; never silently pretend to provide real radio, DAC, USB or stock capabilities.
- Optional reverse-engineering research **tooling**, not required build dependencies: reproducible MIPS ELF/string/disassembly/IPC analysis using appropriately reviewed tools (e.g. `mipsel-linux-gnu-objdump`; agent-facing Ghidra/REA only if separately vetted). Keep any binary provenance, source rights, privacy, authorization and isolation rules. The diskOS public catalogue explicitly identifies `objdump`; it does **not** substantiate which GUI RE framework its authors used.
- Version-scoped protocol maps for verified stock tags, replies, structs/ABI, affected firmware revisions and evidence confidence; do not reuse offsets or command behavior across versions based on version ordering.
- Public examples for all three artifact classes, host-specific integration instructions and full-fork workflows; no private Sorane-only permissions.
- Reports matching **device + firmware main/recovery/rootfs/stock player + runner + UI host + extension/service artifact + adapter + scenario + host + timestamp**. Claims from maintainers and Lab tests remain separate; physical proof is independent.

## 4. Community Update Center: one user experience, distinct trust paths

Goal: a developer/user can check for updates to diskOS, Disco!, Sorane, registered community forks and supported extensions **from Lab**, inspect changes and compatibility, then deliberately prepare or apply only the update type their device/install actually supports.

### Update channels

1. **Lab environment:** reviewed CLI/SDK, runner/shim, adapter and compatibility-profile update, retained old pins, explicit rollback; no change to physical DISC.
2. **UI release/source candidate:** discover trusted upstream release metadata and opt-in community releases; resolve a tag to immutable commit/assets, digest/signature provenance, license and build recipe; compare and test without overwriting the last accepted UI.
3. **UI extension/service candidate:** update only on a UI host that explicitly supports the same extension/API/ABI and deployment model; rebuild/retest dependent UI when statically linked.
4. **Previously installed physical custom UI:** where its owner-enrolled key/installer supports it, create a **locally owner-signed, format-correct UI-only SD package**, after scoped compatibility checks and explicit consent. Never assume signing keys or update formats are interchangeable among diskOS, Disco!, Sorane or forks. Package generation is distinct from installation.
5. **Initial install, switch between custom UIs or full flash:** **not the same as a UI-only update**. Delegate to the appropriate reviewed upstream installer/recovery instructions unless a separately approved scope is designed; check device stock base, backup, possible key replacement and supported migration route first.
6. **Official FiiO firmware main/recovery:** discovery/compatibility advice remains separate, vendor-managed by default; do not auto-download proprietary images, silently flash, or describe a custom UI updater as a vendor firmware updater.

### Desired user flow

1. **Register/choose a project** (diskOS, Disco!, Sorane or approved opt-in fork) and select an installed version or locally provided artifact. Physical-device status may only be read **with explicit consent**, no default USB/device probing.
2. **Check updates**: show current, available and exact pinned revision; maintainer changelog, source and artifact provenance; note whether this is Lab-only, UI-only, extension, migration/full install or official firmware.
3. **Compatibility preview**: exact installed firmware/main/recovery, stock player/ABI, UI build, supported capability set, installed extensions, target update type and test matrix. Unknown remains UNKNOWN; an emulator pass is not a device-safe badge.
4. **Review/update plan**: required prerequisites, build dependencies, signed-package protocol, local key enrollment, backup/recovery instructions, permissions/network risks, impacted data/settings and diff from last accepted version.
5. **Prepare candidate**: only after user opt-in; fetch verified permissible source/artifacts; run untrusted builds without firmware, privileges, credentials or host devices; trusted firmware tests only by separately authorized controlled runtime.
6. **Stage package**: for a supported owner-signed UI-only channel, sign **locally**, verify enrolled public key/signature/manifest/epoch/version, verify hashes and intended destination; never upload private keys, firmware, personal music or device dumps.
7. **Explicit delivery/installation**: show SD copying or the project's documented update procedure. A future on-device action is separate, capability-specific and never unattended. Stop if device/install identity, storage/write guards or compatibility evidence is missing.
8. **Observe outcome**: allow manual/version readback or authorized device acceptance, preserve logs and old metadata, make rollback available **only where the specific installer actually supports and validates it**. A failed or unknown write is not automatically safely recoverable.

The convenience goal is an integrated **Update Center** UI eventually, with CLI/read-only behavior first. A GUI/desktop experience is a later separately reviewed deliverable, not part of current M1 acceptance.

### Candidate upstream release inventory (observation, NOT acceptance)

As reviewed 2026-10-25:

| UI project | Observed release | Annotated release tag resolves to | Lab status |
| --- | --- | --- | --- |
| [diskOS](https://github.com/b0hemia/diskos/releases/tag/v1.2.2) | v1.2.2 (2026-10-24) | `66af1f639fd7c4adbb15f5b605100c3fd5733b8a` | **candidate / NOT RUN** |
| [Disco!](https://github.com/zmd22/diskos-disco/releases/tag/v3.0.0) | v3.0.0 (2026-10-24) | `721e07ee2266466888d84b92e756fd3a4fc778b1` | **candidate / NOT RUN** |

These are **not approved replacements for `upstreams.lock.yaml`** and do not prove reproducible builds, source/licensing acceptability, package-signing compatibility, stock QEMU operation or real-device safety.

## 5. Placement in existing milestones — no new M1 blocker

- **M1:** preserve current stock V2.57 provenance, firmware intake/refusal, trusted isolation and actual baseline gates. Research upstream firmware ZIP/rootfs pins separately; do not borrow another project's looser checks or run firmware to make the roadmap green.
- **M2/M3:** generic UI launch and independently pinned diskOS/Disco! adapters; record new releases as **candidates**, not silent pin updates.
- **M4/M5:** firmware-scoped capability/IPC and **UI host + extension/service** compatibility matrix, source-vs-Lab evidence and physical-vs-QEMU distinctions.
- **M6:** add explicit extension/service development contract, permission/capability manifest, mocks, source-integrated host guidance, example feature/app and Sorane dogfooding alongside the existing `full-ui` SDK.
- **M7:** community release discovery, explicit candidate selection, dependency/release delta reports, update plan/check and regression review; integrate extension candidates, not just full UI/firmware.
- **M8:** last-known-good pins, staged release assets and safe rollback for Lab environment; verify distribution rights/licensing.
- **M9:** opt-in **project-specific physical UI-only update** packaging/signing/SD delivery after device and enrollment validation; separate the initial/full flash and stock firmware channels; hardware acceptance not inferred from emulator.
- **M10:** community registration, extension author guides, user-friendly update-center workflow documentation and transparent support/status reporting.

**Non-goals for now:** universal physical flasher, automatically installing arbitrary GitHub releases, hot-loading native plugins into unmodified community UIs, unattended device writes, unauthorized proprietary redistribution, or claiming every Spotify/Cast/AirPlay setup can run on hardware.
