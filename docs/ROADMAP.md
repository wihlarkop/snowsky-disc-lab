# SNOWSKY DISC Lab — Detailed Roadmap

**Status (2026-10-23):** M0 foundation integrated; subsequent PRs through [#33](https://github.com/wihlarkop/snowsky-disc-lab/pull/33) established pinned firmware-free QEMU execution, first-party synthetic UI input-to-frame acceptance, binary/source preflight and read-only compatibility registry tools. M1 stock V2.57, real firmware extraction, M2 stock player handoff and M3 custom UI acceptance remain open. **No stock firmware/UI combination is Lab-verified.**
**Last upstream UI release review:** 2026-10-23 (Disco! [v2.7.0](https://github.com/zmd22/diskos-disco/releases/tag/v2.7.0)); announced versions are not pins or Lab tests.
**Device scope:** FiiO / SNOWSKY **DISC** only.  
**Companion UI:** **Sorane**, in a separate repository to be created later.  
**Development baseline:** Windows 11 + WSL2/Docker as the primary *target* runtime host, with a Linux CI/native path. Windows/Linux firmware-free CLI evidence does not establish emulator runtime success.

> This document is a plan, **not evidence that features are already shipped**. A completed milestone needs observable artifacts, reproducible commands, tests and a recorded exact commit; a checkbox in a planning document is not a compatibility claim.

## 1. Product contract and design principles

SNOWSKY DISC Lab is an integration platform for official stock firmware, diskOS, diskOS Disco!, Sorane and third-party UI forks. It aims to support multiple firmware revisions **simultaneously**, with stable previously validated combinations instead of inheriting upstream's single-active-firmware maintenance policy.

1. **Support is evidence-driven.** Detecting a firmware, successfully extracting it, booting a UI, passing functional checks and passing hardware checks are distinct states.
2. **Pin immutable inputs.** Every supported combination identifies the firmware/rootfs hash, stock binary fingerprints, QEMU revision, host runtime/toolchain, UI source/build hash and adapter revision. No floating `main` in reproducible runs.
3. **Never silently break older versions.** Old firmware gets isolated state and a retained compatible adapter/runner. Regression failures block promotion of the new candidate; a new emulator revision need not replace the old one.
4. **Build once, test everywhere appropriate.** A community UI should have a single supported input contract, not a custom emulator fork per UI.
5. **Keep upstream boundaries.** Integrate pinned upstream sources via cached fetches; maintain narrow, reviewed changes and send generic improvements upstream. Do not vendor all projects indiscriminately.
6. **No stock firmware in Git.** Firmware must be user-supplied and independently hash-checked; generated files, personal media, signing private keys and device dumps stay local/private.
7. **Separate untrusted builds from trusted firmware runtime.** No proprietary firmware, secrets, hardware passthrough or privileged Docker access in public/untrusted PR jobs.
8. **Emulation is not hardware proof.** QEMU user-mode cannot certify actual MIPS CPU speed, RAM limits, USB gadget, Bluetooth, DAC, suspend/resume, NAND or battery behavior.
9. **No automatic physical flashing.** Initial device install/recovery/SD signing are separate opt-in operations after backups, suitability checks and manual approval.
10. **Small independently shippable PRs.** Each phase has an acceptance gate based on executable behavior. **No TDD, no required unit tests, no coverage targets**: use focused CLI/contract integration checks and later QEMU/regression tests. No frontend is needed to test a CLI.

**Long-term community product direction:** [community development, extension/service experimentation and integrated Update Center](COMMUNITY-PLATFORM-VISION.md). This is future scope, not a new M1 prerequisite or an implemented capability.

## 2. Upstream baseline and support semantics

### Observed upstream state — NOT Lab-tested

| Component | Reviewed state | Boundary |
| --- | --- | --- |
| [diskOS](https://github.com/b0hemia/diskos) | v1.2.1 installer; official V2.09/V2.28/V2.40/V2.57 ZIPs listed | On-device custom LVGL UI and installer; supported install base is not proof of emulator compatibility |
| [diskOS Disco!](https://github.com/zmd22/diskos-disco) | [v2.7.0](https://github.com/zmd22/diskos-disco/releases/tag/v2.7.0) released 2026-10-22; first install still starts from FiiO V2.57 | Expanded UI/themes plus Disc Shelf (Navidrome + experimental SMB3), Shuffle! gesture and controlled on-demand downloads; **not Lab tested** |
| [snowsky-disc-qemu](https://github.com/eudj1n/snowsky-disc-qemu) | `2.x` uses V2.57 as active stock runtime; V2.40 legacy/historical | QEMU user mode, not full-system or general firmware auto-compatibility |
| [QEMU diskOS preview](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/experiments/diskos/docs/preview.md) | Historical experimental custom diskOS `mq_ui` on V2.40 | Pinned old UI commit, warm-player adaptation, known playback limits; **not** a validated Disco! 2.7.0/V2.57 path |

**Important:** retain *Lab's own* per-combination evidence; do not copy an upstream success badge into a Lab test result. Review newer upstream evidence before promoting an updated dependency.

#### Disco! 2.7.0 candidate intake (upstream only)

[Disco! 2.7.0 release notes](https://github.com/zmd22/diskos-disco/blob/main/docs/releases/v2.7.0.md) describe built-in **Disc Shelf** for Navidrome and SMB3, on-demand downloads to SD with cancellation/partial-file semantics, a new menu-hold **Shuffle!** action, SongSphere guard screen, temporary Wi-Fi power-save management and batched writes. [Release](https://github.com/zmd22/diskos-disco/releases/tag/v2.7.0) is the authoritative upstream source; the [Reddit announcement/discussion](https://www.reddit.com/r/snowsky/comments/1xcwvrt/disco_270_less_cable_more_music/) is a community reference, **not validation**. Upstream reports SMB3 as experimental and actual transfer-speed/power benefits as unmeasured. Navidrome/SMB3 network behavior requires separate isolation and credential handling; never run arbitrary network code or import real personal libraries into public CI.

This is **Disco! UI version 2.7.0**, not FiiO stock firmware V2.70. A release tag/semver announcement alone is not an immutable Lab source lock; exact Git commit, assets, dependencies, binaries and rights require M3 review. No M1/M3 acceptance or support status is promoted by this entry.

#### New upstream UI candidates (observed 2026-10-25; NOT RUN)

- [diskOS v1.2.2](https://github.com/b0hemia/diskos/releases/tag/v1.2.2) → exact annotated tag commit `66af1f639fd7c4adbb15f5b605100c3fd5733b8a`.
- [Disco! v3.0.0](https://github.com/zmd22/diskos-disco/releases/tag/v3.0.0) → exact annotated tag commit `721e07ee2266466888d84b92e756fd3a4fc778b1`.
- Candidate inventory only: build, licensing, binary, emulator/device compatibility and update package support are NOT RUN/UNVERIFIED. Preserve current `upstreams.lock.yaml` until independent review; see [community vision](COMMUNITY-PLATFORM-VISION.md).

### Initial firmware coverage targets

- **V2.57:** first integration target: upstream's current stock QEMU + diskOS + Disco! adapters.
- **V2.40:** restore/retain legacy runtime in a version-scoped environment and retest with a pinned runner.
- **V2.28:** new reviewed profile, read-only static analysis, porting, tests; no use of V2.57 offsets without verification.
- **V2.09:** same separate review/porting process; use only legitimate firmware sources.
- **Additional observed version candidates:** V2.21, V1.95, V1.86, V1.77, V1.76, V1.65 and V1.56 are backlog research inputs only. Their ZIPs/metadata have not been independently ingested or authenticated by the Lab, and there are no reviewed runnable Lab profiles for them. See the [README support matrix](../README.md#firmware-version-support-matrix).
- **New versions:** detected as candidates; remain `unknown` until reviewed and tested. Supporting all *known verified* versions is the maintenance objective, not a promise of instant support for all future releases.

## 3. Dependency sequence (critical path)

```text
M0 Repository/contracts/security baseline
   |
   +--> M1 Stock V2.57 emulator baseline
   |      |
   |      +--> M2 External mq_ui launcher/build contract
   |               |
   |               +--> M3 diskOS and Disco! V2.57 integration
   |               |      |
   |               |      +--> M6 Community UI SDK + Sorane dogfooding
   |               |
   |               +--> M4 Historical multi-firmware support (2.40, 2.28, 2.09)
   |
   +--> M5 Compatibility registry/reporting and CI safety
          |
          +--> M7 Upstream / OTA intake automation
          |
          +--> M8 Cross-version regression and release process
                               |
                               +--> M9 Optional physical-device validation
                               |
                               +--> M10 Community-ready release
```

Registry and safety scaffolding start in M0; M5 makes them complete and publicly reportable. Hardware is not required for M0–M8's firmware-free work. Firmware-backed tests require access to official firmware and a controlled, trusted local environment.

## 4. Milestones and issue-ready tasks

### M0 — Bootstrap, scope, locks and public contracts
**Goal:** a safe, understandable empty framework before any firmware execution.

- [x] **M0-00** Create initial README and detailed project planning documentation.
- [x] **M0-01** Establish `src/` or `lab/` package, CLI entry point, dependency policy, supported host matrix, and ignored local cache/work directories.
- [x] **M0-02** Define `upstreams.lock.yaml` schema with immutable commits/tags **resolved to commits**, verified artifact checksums, source license metadata and auditable update procedure. Source-only scope: Git blob integrity and selected license SHA-256 values; no release/build artifacts are selected.
- [x] **M0-03** Define `lab-ui/v1` manifest and `lab-firmware/v1` profile schemas with JSON Schema/strict validation and explicit versioning/deprecation rules.
- [x] **M0-04** Implement firmware-free `disc-lab doctor` checking architecture, Docker Engine/Compose, WSL2 when applicable, toolchain prerequisites, disk space and path/permission issues. **Never write to USB.** Default checks remain metadata/version-only; daemon contact is explicit opt-in and runtime readiness stays unverified.
- [x] **M0-05** Implement `disc-lab sources list|sync|verify`: cache pinned public source projections read-only for consumers; refuse dirty/unrecognized checkout in reproducible mode; offline operation when already cached.
- [x] **M0-06** Add minimal CI for lint/types/schema/fixtures, test contracts and source provenance without proprietary firmware, privileged runners or secrets. PR #4's exact baseline passed all four Linux/Windows Python jobs; later/integrated heads need their own CI evidence.
- [x] **M0-07** Define written trust boundaries, initial SPDX/license inventory and remaining review plan, safe temp directory lifecycle and API/CLI versioning policy. This baseline does not clear pending component rights or choose the Lab core license.
- [x] **M0-08** Publish a precise design/ADR for external UI injection: [ADR 0001](adr/0001-external-ui-handoff.md) records pinned historical evidence, stock player ownership, initial cold-session strategy and deferred exact-combination warm handoff. Design deliverable only; runtime assumptions remain NOT RUN and the ADR is proposed for review.

**Exit gate:** clean clone + documented tooling runs `doctor`, manifest/schema validation and source-lock verification on a supported host; no firmware required; no device access; CI green. `README` does not claim an implemented emulator yet.

Issue #1 delivers M0-01/M0-03 and the initial workflow. M0-02/M0-05 add immutable source projections and offline integrity checks; see [source verification](M0-SOURCES-VERIFICATION.md). M0-04 reports host/tool/cache observations; M0-07 records [trust boundaries](TRUST-BOUNDARIES.md) and [initial license evidence](LICENSE-INVENTORY.md). See [preflight/trust verification](M0-PREFLIGHT-VERIFICATION.md). M0-08 now supplies the handoff design. [Integration readiness](M0-INTEGRATION-READINESS.md) records exact PR #4 CI success and recommends PR #2 → #3 → #4 → M0-08 integration, followed by final-head CI. **M0 is not closed while that review/integration gate remains open.** Runtime/ACL/virtualization and complete redistribution clearance remain unverified; M1 execution needs its own preparation and authorization.

### M1 — Reproducible stock V2.57 QEMU
**Goal:** prove the underlying emulator works on *our* supported host before introducing custom UIs.

- [ ] **M1-01** Pin reviewed QEMU `2.x` commit, Docker image/tool dependencies, official V2.57 rootfs metadata and guest shims. Record known limitations.
  - [Preparation evidence](M1-01-RUNTIME-PREPARATION.md) records immutable source/base-image/recipe/patch identities and upstream firmware references after PR #6's exact integrated-main CI passed. The [runtime reproducibility and Windows/WSL2 report](M1-07-WINDOWS-WSL2-VALIDATION.md) records strict build receipt checks, local host blockers and exact hosted CI results; M1-01 remains open until the new clean-build run and stock-runtime gates are reviewed.
- [ ] **M1-02** Add an explicit, safe local official firmware intake path: ZIP/OTA folder selection, size/contiguity/hash checks, optional verified vendor signature when trust chain is reviewed; fail closed for unknown firmware.
  - [Safe intake foundation](FIRMWARE-INTAKE.md) implements bounded offline ZIP/package inspection, strict V2.57 structure and main-manifest ciphertext checks, and versioned receipts with no extraction/execution authority. Synthetic acceptance only; product/plaintext identity, vendor trust chain and actual-package acceptance remain unverified. Full M1-02 stays open.
- [ ] **M1-03** Extract into per-firmware, per-run isolated ignored volumes; never upload firmware or mount real devices.
  - [M1-03 workspace preparation and synthetic output harness](FIRMWARE-INTAKE.md#m1-03--private-workspace-preparation) provides synthetic-verified private snapshots, package/session identities, bounded quotas, revalidation, no-replace publication, quarantine, limited cleanup and a fixed output-lifecycle fixture bound to one first-party synthetic package digest. The checkbox remains open: this is not a firmware extractor and does not produce proprietary firmware outputs, a decrypted image or a mounted rootfs. The [upstream extraction/toolchain readiness review](M1-EXTRACTION-TOOLCHAIN-READINESS.md) records the pinned extraction call path and confirms that authenticity, licensing, toolchain and isolation gates remain unresolved. Its next recommendation is a firmware-free M1-01 QEMU runtime build.
- [ ] **M1-04** Boot V2.57 stock `mq_ui` + `mq_player`; capture actual framebuffer, log and a reproducible screenshot fixture.
  - The [firmware-free synthetic runtime](synthetic-runtime.md) implements isolated first-party filesystem/session acceptance through the reviewed QEMU build. It does not execute stock binaries; M1-04 remains **NOT RUN / unverified**.
- [ ] **M1-05** Test touches/swipes/physical key model, SD import/index, local PCM output and WAV fixture comparisons.
- [ ] **M1-06** Test stop/restart/power lifecycle and persistent guest data isolation; document qemu-user timing and hardware limitations.
- [ ] **M1-07** Verify Windows 11 + WSL2/Docker path separately from Linux; do not assume Docker Desktop behavior matches native Linux.
  - [Windows/WSL2 validation](M1-07-WINDOWS-WSL2-VALIDATION.md) records CLI access-denied results for WSL2/CIM and an unavailable Docker Engine pipe. No local QEMU or synthetic runtime was run; M1-07 remains open.
- [ ] **M1-08** Produce a provenance-rich V2.57 stock test report with precise revision/hash, host details and measured timings where observed (not hardware-FPS claims).

**Exit gate:** a new trusted environment can reproduce stock V2.57 boot, input, media scan, full short-track PCM playback and guest restart with artifacts attached locally; no physical DISC writes.

### M2 — Generic external UI adapter and launcher
**Goal:** run a non-stock `mq_ui` without hardcoding a particular UI fork.

- [ ] **M2-01** Version and implement UI adapter interface for `inspect`, `build`, `preflight`, `launch`, `stop`, `collect`, `report`. Preparation is internal to `launch`; follow [ADR 0001](adr/0001-external-ui-handoff.md) after stock M1 acceptance.
- [ ] **M2-02** Accept **local binary mode**: inspect static/dynamic ELF, MIPS32-LE ABI, soft/hard float expectations, library dependencies, size, hashes and required filesystem paths before attempting execution.
- [ ] **M2-03** Define **source mode**: local path or exact Git URL + immutable commit, trusted/pinned build recipe, output fingerprint, reproducible build record; no arbitrary auto-build on privileged guest.
- [ ] **M2-04** Implement cold-session UI handoff/supervision without UI-specific edits to stock `mq_player`. Own both UI/backend lifetimes, identity/readiness, private mqueues/framebuffer/touch and bounded cleanup. Warm replacement stays deferred until an exact-combination adapter has dedicated evidence; no automatic fallback.
- [ ] **M2-05** Add adapter capability declarations and `unsupported`/graceful-skip semantics; never silently emulate a missing command as a success.
- [ ] **M2-06** Build a tiny synthetic/demo UI contract fixture with no proprietary dependencies and verify input + framebuffer + clean exit.
- [ ] **M2-07** Add `disc-lab ui inspect`, `run --firmware 2.57 --ui <local binary>` and `test --suite ui-smoke`.
- [ ] **M2-08** Add crash artifacts, exit codes, frame snapshots, timeline and structured per-scenario reports.

**Exit gate:** the identical externally supplied binary is tested through the public adapter boundary, without modifying lab core or providing special-case Sorane behavior. Unknown/invalid binaries are refused or clearly reported.

### M3 — Official community UI adapters: diskOS and Disco!
**Goal:** use M2's generic contract for actual current upstream UI projects.

- [ ] **M3-01** Define pinned **diskOS** build preset from its exact source commit and vendored LVGL/toolchain expectations; preserve original LICENSE/COPYING notices.
- [ ] **M3-02** Build a reviewed diskOS `mq_ui`; obtain firmware-free host render/smoke artifacts before guest execution.
- [ ] **M3-03** Adapt and test diskOS on **stock V2.57 `mq_player`** in QEMU; do not equate prior historical V2.40 proof with current compatibility.
- [ ] **M3-04** Define pinned **Disco!** build preset from an independently resolved immutable upstream commit, starting with the [v2.7.0 candidate](https://github.com/zmd22/diskos-disco/releases/tag/v2.7.0); review theme assets, licensing, cross-toolchain, dependencies, host renderer and exact output artifact identity. Do not treat the release tag alone as a trusted pin.
- [ ] **M3-05** Adapt and test a pinned Disco! build on the stock V2.57 player. Verify menu/touch, library, playback/queue, artwork/lyrics (where meaningful), settings, restart, state persistence and intentional differences across shipped themes. Do not infer compatibility from upstream's physical-device reports.
- [ ] **M3-06** Compare stock/diskOS/Disco! against the same generated media fixtures and input scripts, recording expected intentional differences.
- [ ] **M3-07** Detect upstream breakages by building a **candidate revision separately**, never replacing accepted pinned adapters until test evidence is reviewed.
- [ ] **M3-08** Add **Disco! 2.7.0 Disc Shelf** acceptance scenarios: offline first-party mocks for Navidrome vs encrypted SMB3, original-file/collision/path policies, partial/cancel/retry behavior, no background sync, SD write bounds, menu-hold Shuffle!, and temporary Wi-Fi power-save restoration. Any real network server, credentials, trusted V2.57 guest execution or physical-device claims require their own explicit opt-in, isolated evidence and limitations; SMB3 is upstream-experimental, never silently PASS.

**Exit gate:** both upstream UIs have their own repeatable V2.57 reports with actual evidence. If any combination remains partial, document precisely and retain M3 open rather than marking it fully supported.

### M4 — Multi-firmware support without regressions
**Goal:** preserve multiple validated versions at once rather than migrate a single mutable work volume.

- [ ] **M4-01** Revalidate V2.40 historical runtime and exact-version fingerprints on a pinned compatible QEMU runner; compare against archived upstream evidence.
- [ ] **M4-02** Implement V2.28 firmware inventory + static compatibility report before any guest launch. Verify rootfs/ELF/patch addresses independently.
- [ ] **M4-03** Port V2.28 emulator/shims/profile as needed and test stock boot, frames, touch, indexing, playback and lifecycle.
- [ ] **M4-04** Implement V2.09 firmware inventory, independent patch/profile review and stock emulator acceptance.
- [ ] **M4-05** Maintain a compatibility mapping of **firmware → safe runner/adapter** so modern emulator changes cannot silently invalidate archived versions.
- [ ] **M4-06** Separate disk/volume/config/SD fixtures by firmware and run identity; test that switching versions never cross-contaminates guest state.
- [ ] **M4-07** Evaluate diskOS/Disco!/Sorane per firmware **individually**. A UI supporting V2.57 must not be assumed to support V2.09/V2.28/V2.40.
- [ ] **M4-08** Add migration/retirement policy: no silent deletion of validated snapshots, no forced reinterpretation of old firmware profiles, clearly label unmaintained and blocked combinations.

**Exit gate:** at least stock V2.57 plus one earlier version can be selected and independently tested without downgrading the working baseline; remaining versions have separate explicit statuses, not falsified green checks. Completing the full target requires V2.09/V2.28/V2.40/V2.57 stock acceptance.

### M5 — Compatibility registry, evidence and diagnostics
**Goal:** make support claims queryable and test-result backed.

- [ ] **M5-01** Model support per **device/product, firmware main/recovery/rootfs hash, stock player ELF hash, emulator/runner revision, UI binary/source hash, adapter revision, and scenario**.
- [ ] **M5-02** Separate states: `unknown`, `inventoried`, `static-compatible`, `partial`, `verified-emulator`, `verified-device`, `rejected`, `stale`. Missing tests remain unknown, not pass.
- [ ] **M5-03** Store evidence: test commands, timestamps, host fingerprint, screenshot hashes, PCM comparison, exit codes, logs (scrubbed), expected/observed feature coverage and known limitations.
- [ ] **M5-04** Create CLI `compat list|show|compare|report`; machine-readable JSON + human-readable Markdown, with an explicit source field (`upstream` vs `lab-run`).
- [ ] **M5-05** Implement regression diff against last accepted combination and classify failures by build, ABI, input, framebuffer, IPC, audio, power or environment.
- [ ] **M5-06** Add optional performance observations: frame cadence, command latency, CPU throttling experiments and guest memory *trends*, always distinguished from physical device FPS/RSS.
- [ ] **M5-07** Version the evidence schema and make report generation deterministic for the same source results.
- [ ] **M5-08** Extend candidate compatibility to UI-host extension API/ABI, source-integrated module/service artifact identities, required capabilities/permissions and firmware-specific feature test coverage; never infer plug-and-play support for an unmodified UI.

**Exit gate:** `compat report` cannot label an untested, outdated or mismatched artifact Verified; trace from a visible result back to exact hashes and scenario evidence works.

### M6 — Public UI plugin SDK, fork onboarding and Sorane
**Goal:** remove dependence on internal emulator knowledge for UI contributors.

- [ ] **M6-01** Publish `lab-ui/v1` schema, local binary and pinned Git source examples, feature declarations and compatibility rules.
- [ ] **M6-02** Provide reusable build presets (`diskos-musl`, `disco-musl`) and an explicit escape hatch for reviewed custom build steps.
- [ ] **M6-03** Build a **firmware-free UI development kit** with mocked POSIX message queues/player events, synthetic music library, touch/key events and screenshot fixtures.
- [ ] **M6-04** Provide author workflow docs: fork → manifest → host render → local build → optional trusted emulator run → attach compatibility report to PR.
- [ ] **M6-05** Treat unknown public forks as **untrusted input**. Build with no firmware/secrets/privileged Docker; trusted user explicitly opts into running produced binaries in a separate runtime.
- [ ] **M6-06** Add at least one **external** example UI and run exactly the same documented public commands against it. It cannot import private lab internals.
- [ ] **M6-07** Create **Sorane** as a separate repository once the SDK boundary is usable. Sorane's unique design, themes, screens, branding and GPL-obligated derivative UI code belong there, not in the MIT-intended Lab core.
- [ ] **M6-08** Verify plugin compatibility and manifest errors with intentionally malformed and breaking sample forks.
- [ ] **M6-09** Design a distinct, versioned `ui-extension` contract for source-integrated modules and explicitly opted-in host extension points; document which UIs support it and refuse unsupported host/API versions.
- [ ] **M6-10** Design a `service-app` contract for optional network/audio/metadata tools with declared filesystem, network, PCM, process, resource and lifecycle permissions; no privileged defaults or universal plugin ABI claims.
- [ ] **M6-11** Provide firmware-free examples and mocks for a custom screen and an auxiliary service (e.g. radio or AirPlay-like test fixture), with reproducible UI-host integration instructions; external service licensing/hardware feasibility remain separate.

**Exit gate:** a contributor without a real DISC or private FiiO firmware can compile/test/preview a synthetic UI; a trusted developer with locally supplied official firmware can opt into end-to-end QEMU validation.

### M7 — Upstream updates and firmware discovery
**Goal:** identify candidates promptly without destabilizing accepted releases.

- [ ] **M7-01** Track diskOS, Disco!, QEMU GitHub releases/commits (including Disco! v2.7.0 feature/evidence changes); produce issue/PR proposals instead of updating immutable locks in place.
- [ ] **M7-02** Integrate documented FiiO OTA *metadata-only* detection as an isolated monitor. Parse the source→target map; include main OS **and recovery** versions. A missing source route is not "up to date".
- [ ] **M7-03** Deduplicate candidate notifications; record evidence of observation, provenance and changed metadata.
- [ ] **M7-04** For **authorized** firmware downloads only: verify HTTPS/redirects, safe filenames, encrypted manifest/chunk hashes, assembled rootfs hash, and vendor signature when trust chain is established.
- [ ] **M7-05** Run static ELF/ABI/library/IPC/protocol comparison against known-good versions; treat address changes and unknown builds as **requires review**, never copy another version's offsets.
- [ ] **M7-06** Generate candidate support report and proposed exact-pinned lock update. Do not execute new firmware on privileged QEMU or auto-merge from untrusted events.
- [ ] **M7-07** Add notification rules for `new firmware detected`, `candidate tests failed`, and `candidate ready for maintainer review`.
- [ ] **M7-08** Test false positives, malformed OTA JSON, duplicate versions, recovery-only changes, outages, hash mismatch and secrets leakage.
- [ ] **M7-09** Add compatibility orchestration on new FiiO firmware: baseline new stock image on a reviewed runner, then run **opted-in registered** diskOS, Disco!, Sorane and community fork adapters against exact firmware/UI hashes. Unknown/NOT RUN is never compatible.
- [ ] **M7-10** Present an evidence-backed matrix (emulator vs physical test distinctions), source/recovery update route, last test date and actionable blockers. Never auto-run arbitrary fork code with privileged firmware access.
- [ ] **M7-11** Provide initial read-only `disc-lab update check` / `update candidates` workflow with no automatic firmware installation, no proprietary packages distributed, and no surprise upgrades.
- [ ] **M7-12** Add opt-in registered community UI and extension release discovery; exact immutable source/assets, provenance, signing format, migration requirements and a compatibility-aware candidate update plan; no auto-promotion.
- [ ] **M7-13** Design a single Community Update Center (CLI first, optional GUI later) showing installed/selected revisions, release changes, exact compatibility evidence, blockers, prerequisites and a safe action type per project (Lab-only, UI-only package, source-integrated rebuild, initial/full install or vendor firmware).

**Exit gate:** a simulated new V2.xx release creates a clearly unknown candidate with no changes to accepted profiles and no unauthorized execution; a failure never masquerades as "fully compatible."

### M8 — Release, CI matrix and long-term maintenance
**Goal:** stable community operation across old/new firmware and UI forks.

- [ ] **M8-01** Build matrix with public firmware-free jobs and separate **trusted, manually triggered** firmware integration jobs (or local-only runs).
- [ ] **M8-02** Add stable golden inputs and targeted integration suites: build, boot, touch, screens, library, PCM, queue, lifecycle, persistence.
- [ ] **M8-03** Define required gates by type: docs, UI-only, firmware profile, shim/runner, security, release; long idle/USB simulations remain opt-in where justified.
- [ ] **M8-04** Add known-good runtime pins and reproducible cache restore per supported firmware; verify previous versions before accepting dependency updates.
- [ ] **M8-05** Provide versioned CLI/SDK changelog, deprecation windows and migration guides. Changes to manifest/adapter APIs require compatibility tests.
- [ ] **M8-06** Validate dependency/source licenses and notices in distributable artifacts; exclude stock/vendor binaries and private secrets.
- [ ] **M8-07** Maintain a public support matrix with exact last-test date and limitations; stale evidence cannot imply recent verification.
- [ ] **M8-08** Publish a source-only release with installation and troubleshooting docs once the minimal verified baseline exists.
- [ ] **M8-09** Design optional **Lab environment** updater: pin/verify reviewed runner/CLI updates, preserve old working versions and rollback. This is not a FiiO device firmware updater.

**Exit gate:** an intentional breaking upstream candidate fails promotion while the last accepted set still runs; release links only to artifact types safe to distribute.

### M9 — Physical DISC verification and optional UI delivery
**Goal:** measure behavior that qemu-user cannot establish, with explicit user consent.

- [ ] **M9-01** Document device model, installed firmware/version/partition prerequisites, USB/boot-ROM identification and verified recovery procedure; do not rely on assumptions from an emulator.
- [ ] **M9-02** Define music/SD backup and recovery-image retention off-device. Recognize that the diskOS saved stock rootfs is **rebuilt from vendor firmware**, not necessarily a full personal NAND partition dump.
- [ ] **M9-03** Require separate explicit permission for any initial system flash; keep the host awake, stable data cable and checked image/firmware base; stop on validation failure.
- [ ] **M9-04** For a compatible installed diskOS variant with pre-enrolled public update key, support UI-only **signed SD-card update** as the normal iteration path; preserve private signing keys locally and never auto-rotate.
- [ ] **M9-05** Compare emulator against DISC for navigation accuracy, touch responsiveness, animation fluidity, RAM limits, battery/power, playback, headphone/BT/USB behavior and cold-boot stability.
- [ ] **M9-06** Maintain hardware acceptance reports separate from emulator reports; record which features are not modeled.
- [ ] **M9-07** Document abort/recovery steps before any write. Interrupted/unknown writes require following the installer's wait/recovery instructions; recovery is not guaranteed.
- [ ] **M9-08** Research a separate, opt-in **custom UI update package** path using owner-signed SD updates after correct key enrollment and validation; never auto-install. Official FiiO main/recovery updates remain vendor-managed unless a distinct reviewed, explicitly approved device-update scope is opened.
- [ ] **M9-09** Implement only independently reviewed project-specific signed UI-only package preparation/staging after explicit owner consent, compatible installed-base/public-key enrollment, manifest/epoch/hashes and backup checks; never assume diskOS, Disco!, Sorane and forks share signing or update formats.
- [ ] **M9-10** Define a read-only installed-UI/device discovery path when authorized, per-project update/migration decision, post-install readback and mechanism-specific rollback/recovery disclosure. Switching UI families or initial/full flashing cannot masquerade as a UI-only update.

**Exit gate:** separate hardware-specific outcomes recorded; no `verified-device` state from emulator-only evidence; no unattended firmware flash or device wipe.

### M10 — Community contributor experience
**Goal:** external developers can extend the Lab safely and predictably.

- [ ] **M10-01** Contributor guide for firmware-free issues, example forks, UI SDK/adapter and safe reproducible bug reports.
- [ ] **M10-02** PR templates for UI adapter, firmware profile, emulator fix, security and docs; required test/evidence checklist per type.
- [ ] **M10-03** Public sample apps and mocked media library, screenshot/video documentation and a minimal first-fork tutorial.
- [ ] **M10-04** Security disclosure contact/process, maintenance ownership, code of conduct and governance appropriate for community scale.
- [ ] **M10-05** Publish compatibility registry schema, supported matrix, contribution onboarding and a stable SDK release.
- [ ] **M10-06** Track upstream patches and keep third-party author credits/licenses explicit.
- [ ] **M10-07** Document author registration and host opt-in, user-facing community release/update review flows, capability/permission safety and the difference between emulator, device, upstream and untested claims.

**Exit gate:** an unaffiliated contributor can add or update a UI adapter through a reviewable PR without private firmware or access to maintainer secrets.

## 5. Command direction (runtime commands remain design sketches)

Current CLI includes `doctor`, source commands, `firmware inspect`/workspace operations, `ui inspect`, and `compat list|show|compare|report`; build/run/test/update orchestration remains future work. See [CONTRACTS.md](CONTRACTS.md), [FIRMWARE-INTAKE.md](FIRMWARE-INTAKE.md), [M5-COMPATIBILITY-REGISTRY.md](M5-COMPATIBILITY-REGISTRY.md) and [SOURCES.md](SOURCES.md) for implemented syntax and safety limits.

```sh
disc-lab doctor
disc-lab sources sync                # implemented; lock is always enforced
disc-lab firmware inventory --archive /path/to/official-v257.zip
disc-lab firmware profiles
disc-lab ui inspect ./build/mq_ui
disc-lab ui build --repo https://github.com/example/my-disc-ui --ref <sha>
disc-lab run --firmware 2.57 --ui ./build/mq_ui
disc-lab test --firmware 2.57 --ui ./build/mq_ui --suite ui-smoke
disc-lab compat list
disc-lab compat report --firmware 2.57
disc-lab update candidates
```

No `flash` command is in the MVP. If hardware deployment is introduced later, it must use a separately approved, gated action, not a flag hidden inside `run`.

## 6. Test strategy and acceptance definitions

| Layer | Runs on public fork PRs? | Requires stock FiiO firmware? | Primary assertion |
| --- | --- | --- | --- |
| Schema + manifest + lock checks | Yes | No | Invalid/unpinned inputs fail |
| CLI `doctor` contract tests | Yes | No | Read-only, clear diagnostics |
| Host-render + synthetic UI/mqueue fixtures | Yes | No | UI and IPC contract can be tested independently |
| Build sandbox + ELF inspection | Yes, no privileged access | No | Artifacts and architecture conform |
| Stock QEMU guest tests | **No** for untrusted PR | Yes, locally supplied | Reviewed firmware/profile, boot and behavior verified |
| Third-party UI guest integration | Trusted opt-in only | Yes | No privileged CI build stage, per-scenario evidence |
| Hardware acceptance | Never automatic | Physical user device | Separate real-device observations |

An emulator test is **PASS** only after its actual expected postconditions are observed (e.g., a new framebuffer *and* responsive touch, or PCM bytes compared with source). A log saying `booted` or an IPC send being acknowledged is not enough. Tests that are not run are `NOT RUN`, not pass.

Every release candidate must at minimum satisfy focused firmware-free tests; support promotion additionally needs the relevant clean-volume firmware and UI end-to-end acceptance plus regression of all previously accepted combinations potentially affected by the change.

## 7. Risks and mitigations

| Risk | Impact | Planned mitigation |
| --- | --- | --- |
| Upstream ABI/build/source changes | Broken UI builds or runtime | Locked commits; contract versions; candidate PR; regression gate |
| Reusing QEMU V2.57 patches on earlier firmware | Crashes or unsafe execution | Exact ELF SHA-256 and expected bytes; per-version offsets; fail closed |
| Upstream drops legacy V2.40 runtime | Old firmware stops working | Version-scoped frozen runner + retained test evidence |
| Untrusted community fork executes arbitrary code | Host/secret exposure | Nonprivileged no-secret build; reviewed/opt-in guest; isolate firmware and host |
| Docker privileged guest / shared host kernel | Host compromise | Never run public PR code with firmware or privileged runtime; dedicated controlled environment and restricted mounts/network |
| Vendor OTA metadata disappears or changes | Missed/false release detection | Distinguish unknown/error from no-update; pinned archives where permitted |
| QEMU timing differs from physical X2000 | Misleading performance claims | Emulator-only status; separately measured hardware acceptance |
| UI adaptation breaks stock `mq_player` startup | Playback hangs/stops | Cold/warm contracts; full track PCM and restart/queue regression |
| Firmware, keys or personal music leaked | Legal/security/privacy impact | Git ignore, local paths, redacted logs, artifact allowlist, secret scanning |
| Physical flash interruption | Device may not boot | No automatic writes; manual consent, backups and documented recovery; never guarantee recovery |
| GPL/MIT boundaries confused | Distribution compliance risk | Separate Sorane repo and derivative GPL sources; notices and review |

## 8. Definition of done (project-wide)

For a milestone to be marked complete, record:

- exact source commits/tags resolved to immutable SHAs, versioned profile and toolchain versions;
- tested host and architecture (including Windows/WSL when claimed);
- clean-environment reproduction instructions and retained nonproprietary report artifacts;
- CI/test status with specific `PASS`, `FAIL`, `NOT RUN`, `UNSUPPORTED` and open limitations;
- rollback strategy for core dependency/profile promotions;
- security and licensing review for any new execution/distribution boundary.

**Suggested first M1 task after M0 integration:** **stock V2.57 QEMU runtime preparation**: pin runner/container/toolchain/patches and review lawful local firmware identity/authenticity, isolation, cleanup and export policy before implementing intake or executing firmware. Establish the stock baseline before M2 external UI adapters; do not add flashing.

**Additional design:** [Firmware updates, compatibility orchestration and safe update paths](UPDATE_MANAGER.md). This deliberately separates read-only OTA detection, verified Lab runtime upgrades, owner-signed UI-only SD packages and high-risk official device firmware changes.

## 9. References (primary upstream documentation)

- [diskOS](https://github.com/b0hemia/diskos), [installation and recovery](https://github.com/b0hemia/diskos/blob/main/docs/INSTALL.md), [custom UI](https://github.com/b0hemia/diskos/blob/main/ui/README.md)
- [diskOS Disco!](https://github.com/zmd22/diskos-disco), [theme framework](https://github.com/zmd22/diskos-disco/blob/main/themes.md), [development / signed SD updates](https://github.com/zmd22/diskos-disco/blob/main/docs/DEV_WORKFLOW.md)
- [QEMU repo](https://github.com/eudj1n/snowsky-disc-qemu), [current emulator status](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/emulator/docs/status.md), [hardware/timing limitations](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/emulator/docs/limits.md)
- [QEMU firmware profile contract](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/firmware/docs/firmware-profiles.md), [firmware porting](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/firmware/docs/porting.md), [OTA monitoring](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/firmware/docs/ota.md), [historical diskOS preview](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/experiments/diskos/docs/preview.md)
