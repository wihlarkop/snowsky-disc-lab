# Update Manager — FiiO Firmware Detection, Compatibility Matrix and Optional Update Paths

**Status:** design proposal, **not implemented**. Prepared 2026-10-19. The official FiiO stock firmware must be acquired from authorized sources; SNOWSKY DISC Lab does not distribute proprietary images.

This document specifies a **first-class product feature**: when FiiO releases a new DISC firmware, identify it, investigate changes, assess registered community UIs (diskOS, Disco!, Sorane and other opt-in forks), and provide transparent **evidence-based compatibility results**. Safe update experiences are a distinct phase from merely discovering an OTA release.

## 1. Three very different meanings of "update"

| Update channel | Target | Permitted behavior | Not permitted by default |
| --- | --- | --- | --- |
| **Lab update** | Developer's local CLI, verified firmware profiles, QEMU runners, UI adapters and SDK | Install reviewed versioned Lab release / runner with rollback and retained old pins | Silent upstream head tracking, overwriting last good version, running unreviewed FiiO firmware |
| **Custom UI update** | A previously installed diskOS/Disco!/Sorane UI on a physical DISC | After proven compatibility and the owner's permission, prepare **UI-only signed SD update** using existing owner enrollment/key material locally | Uploading keys, accepting another owner's signing key silently, overwriting stock `mq_player`, unattended install |
| **Official FiiO firmware update** | DISC stock main OS/recovery/kernel/boot chain | Detect from vendor OTA, advise official route, verify selected official package and applicable device/base if user explicitly opts in to future installer research | Auto-flash, claiming a custom-image installer is official FiiO updater, bypassing hash/base checks, assuming updated official firmware preserves diskOS installation |

**MVP shall only implement read-only discovery and status**. "Update from Lab" for the *developer environment* can follow earlier than any physical-device update. **Physical firmware writing is not part of the emulator MVP.**

## 2. Vendor update detection (FiiO)

Research from [QEMU OTA documentation](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/firmware/docs/ota.md):

- Official OTA metadata is obtained through the device's vendor service; the observed response provides **source-version → target-version** update routes plus recovery revision, not just one `latestVersion`.
- A source version without an OTA route is **not** proof of being up to date.
- Their GitHub Actions metadata monitor checks daily and raises an issue for a newly advertised main-OS/recovery pair. Its behavior is for QEMU upstream; Lab must build its own trusted status registry and workflow.
- The endpoint may serve an explicitly documented trailing comma; parser must validate strict fields, bounds, HTTPS, allowed vendor deviations, timeouts, schema and duplicate/malformed routes.
- The vendor can publish encrypted package chunks, signed manifests and checksums. Availability or successful download is **not a compatibility proof**. The upstream research verified only a representative subset of files; don't claim full OTA acquisition until actually implemented and validated.
- CI monitoring needs **metadata only**. Never execute unreviewed downloaded firmware just because an OTA endpoint advertises it.

Proposed discovery loop (later milestone):
1. Poll official metadata on a scheduled trusted CI workflow with rate limiting and failure reporting.
2. Detect a new target **main + recovery** combination, version-specific update routes, or changed advertised metadata.
3. Record candidate with `detected` state and source/provenance; create/update an issue and deduplicate notifications.
4. On candidate review, obtain official package **through authorized means**, verify exact identity, archive/chunk hashes, signature (where a verified vendor public-key/trust chain is available), and static changes.
5. Never mutate last accepted firmware profiles, adapters or viewer runtime in place.

## 3. Compatibility orchestration for every registered UI

A UI fork may **opt in** through a versioned `lab-ui/v1` manifest or registry entry containing a Git revision/binary SHA, build preset and claimed firmware targets. Lab must not automatically discover/run every random GitHub fork or execute arbitrary build scripts.

Matrix keys include:
- Hardware target + stock main/recovery + rootfs and exact player ELF fingerprint.
- Pinned QEMU runner/hardware shims/adapter revision.
- UI source commit, compiled binary fingerprint, build preset and UI adapter revision.
- Scenario and host environment; separate `emulator` versus `real-device` evidence.

**Release event → candidate registry → static preflight → safe build/host checks → trusted emulation suite on reviewed package → feature matrix + report.**

Example **fictional, illustrative** status after a hypothetical FiiO V2.60 announcement:

| UI | V2.57 + accepted runner | V2.60 candidate | Meaning |
| --- | --- | --- | --- |
| Stock FiiO UI | Verified upstream / requires Lab recheck | Unknown / review required | First establish new stock baseline |
| diskOS pinned release | Independently scoped result | Not run | Rebuild or inspect exact matching artifact |
| Disco! pinned release | Independently scoped result | Partial only if tests actually prove it | Historical / different OS base not inherited |
| Sorane pinned build | Independently scoped result | Not run | Same public plugin rules as third-party forks |
| Registered community fork | Own independent result | Unknown until run | Contributor claim is not verification |

**No universal compatibility guarantee:** even if the Lab runs all *registered/reproducible* fork scenarios, it cannot automatically establish all on-device hardware behavior or compile a fork with an arbitrary unreviewed build setup. Unknown, blocked, partial, unsupported, error and untested must be visible rather than replaced with optimistic passes.

## 4. Automatic regression candidate gate

When an accepted UI or QEMU runner is updated independently of FiiO:
1. Preserve its last passing, exact-commit snapshot.
2. Generate a candidate with its own runner, firmware rootfs, virtual SD and results folder.
3. Build source in a **nonprivileged/no-secret sandbox**; validate the artifact and static ABI first.
4. Trusted, deliberately opted-in firmware integration may run only after reviewing candidate code and required privileges.
5. Compare against previously accepted scenarios for **every affected firmware/UI tuple**.
6. Candidate stays pending if required checks fail, are not run or review is incomplete; never upgrade a known-good environment without a user choice and rollback path.
7. When ready, publish a signed/hashed Lab release asset and compatible runner/adapter (future design) with changelog/evidence references; no proprietary firmware binaries inside Lab distributions.

## 5. User experience: planned update center

An eventual `disc-lab update` CLI group (not implemented):

```text
disc-lab update check                 # metadata/read-only: Lab + upstream + FiiO
disc-lab update candidates            # new firmware/UI runner candidates
disc-lab compat matrix --firmware 2.60
disc-lab update plan --target lab      # reproducible report; old version retained
disc-lab update apply --target lab     # future opt-in; explicit user confirmation
```

For custom UIs, prefer a **separate** `ui package` / `ui sign` workflow when M9 is reached. It must require owner-controlled private keys (never uploaded), matching enrolled public key and full manifest/epoch validation. An optional UI-only deployment workflow must follow the verified diskOS signing + SD-card updater documentation, not invent its own on-device privilege mechanism.

### Notification categories

- `firmware-released` — new main/recovery pair detected.
- `static-review-needed` — package obtained but unverified features/ABI/patches.
- `compatibility-partial` — some checks pass, required checks missing or failed.
- `compatibility-verified-emulator` — exact tested combinations only.
- `hardware-verification-needed` — emulator is insufficient for power, USB, DAC, NAND, Bluetooth and physical performance.
- `lab-update-ready` — a reviewed local development tool/runtime upgrade is available with rollback.
- `ui-update-package-ready` — owner-signed UI-only SD package prepared after authorized setup; not automatically installed.

Avoid notification spam by hashing exact target pair, profile and candidate revision. Reports must specify last-tested date.

## 6. Integration with roadmap

- **M0:** reserve update state semantics in docs; do **not** implement OTA or privileged firmware downloads yet.
- **M1:** establish trusted stock V2.57 firmware baseline before testing arbitrary UI candidates.
- **M2–M3:** build generic adapter contract and real diskOS/Disco! integration; no auto-promoted compatibility.
- **M4–M5:** multi-firmware profiles + evidence-backed per-feature matrix.
- **M6:** community fork registration; Sorane uses identical contract.
- **M7:** vendor OTA and upstream release detection; candidate static analysis and *controlled* compatibility orchestration, optional maintainer alerts.
- **M8:** reviews, regression suite, safe Lab/runtime release/upgrade with rollback.
- **M9:** optional physical-device validation, UI-only signed SD packages; official FiiO firmware update support only as a separately reviewed high-risk scope, not implicit device-flashing feature.

## 7. Security and legal constraints

- Do **not** redistribute FiiO ZIP files, rootfs, encrypted package chunks, stock `mq_player`, device data or unlicensed firmware-derived assets.
- Keep proprietary firmware, decrypted images and logs containing user metadata outside Git and public CI artifacts.
- Do not run untrusted PR/fork code in privileged QEMU user-mode Docker (shared VM kernel), or with credentials, rootfs secrets, device USB access, private signing keys or host mounts.
- Vendor package integrity, vendor authenticity, emulator compatibility, diskOS install-base compatibility and real-device upgrade safety are **separate checks**.
- A stock FiiO firmware update may replace or invalidate custom diskOS/Disco!/Sorane changes or owner key enrollment. Verify behavior per version and install method before recommending a path. Do not guess that a vendor OTA upgrade preserves customization.
- Never bypass exact-version/ELF/hash/write guards; no automatic physical flash or forced rollback/recovery operation.
- An emulator integration PASS is never a guarantee that physical upgrade is safe.

See [compatibility policy](COMPATIBILITY.md), [roadmap](ROADMAP.md), [architecture](ARCHITECTURE.md), and [technical stack](TECH_STACK.md).
