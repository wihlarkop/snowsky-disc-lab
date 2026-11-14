# Firmware, UI and Emulator Compatibility Policy

**Status (2026-10-23):** These are the Lab's compatibility rules and upstream research references, **not evidence that stock firmware/third-party UIs have run**. The read-only M5 registry and CLI exist, while authenticated evidence promotion and stock acceptance remain open. Pinned handoff research: 2026-10-20 ([ADR 0001](adr/0001-external-ui-handoff.md)); Disco! release research updated 2026-10-23. Stock-backed external UI launch remains deferred until M1 acceptance.

## 1. What does "supported" mean?

Do **not** reduce support to a version number. One reported result is a tuple:

```text
device hardware/revision
+ stock firmware main/recovery version
+ stock rootfs SHA-256
+ mq_player / mq_ui / system library fingerprints
+ QEMU runner/shim/toolchain revision
+ UI source commit and exact built ELF SHA-256
+ UI adapter revision and manifest schema version
+ host environment / test suite / scenario
+ evidence timestamp and results
```

A successful native diskOS install, for example, **does not** prove that the same `mq_ui` works in QEMU; a successful emulator boot **does not** prove hardware safety. For combined firmware/UI support, the entire tuple must be tested.

### Proposed status vocabulary

| State | Meaning |
| --- | --- |
| `unknown` | Not reviewed, evidence missing, new revision or mismatched fingerprint |
| `inventoried` | Source package identity/rootfs information recorded; no execution |
| `static-compatible` | ELF/dependencies/protocol assumptions reviewed; behavior not yet proven |
| `partial` | One or more named scenarios pass; required scenarios not yet complete or fail |
| `verified-emulator` | Defined emulator acceptance suite passed on exact pinned inputs |
| `verified-device` | Separate in-person physical acceptance passed for named hardware/firmware/UI; scope must be listed |
| `rejected` | Known mismatch or safety check refusal, with reproducible reason |
| `stale` | Historical accepted evidence is retained but no longer current for a newly changed input or maintenance policy |

Also report `PASS`, `FAIL`, `NOT RUN`, `UNSUPPORTED`, `BLOCKED` per test. These are test outcomes, not the same as overall support status. `untested` and `unsupported` are not interchangeable.

**No automatic promotion:** manifest claims, semver ranges, release announcements, screenshot renders and reused offsets cannot set `verified-emulator` by themselves.

## 2. Upstream references versus Lab firmware support

The following is **documentation-derived** and has **not** been validated on stock firmware by this Lab. The [README firmware matrix](../README.md#firmware-version-support-matrix) distinguishes the four roadmap targets from additional unprofiled candidates.

| Firmware | diskOS v1.2.1 installer base | Disco! v2.7.0 first-install base | QEMU upstream | Lab stock status |
| --- | --- | --- | --- | --- |
| 2.09 | Listed supported | Not a declared supported base | No runtime profile | **NOT RUN** |
| 2.28 | Listed supported | Not a declared supported base | No runtime profile | **NOT RUN** |
| 2.40 | Listed supported | Not a declared supported base | Historical runtime/experimental old diskOS preview | **NOT RUN** |
| 2.57 | Listed supported | V2.57 required by upstream for first install | Active stock runtime | **NOT RUN** |
| Future version | Unknown | Unknown | Must be ported | **UNKNOWN** |

Source references: [diskOS install](https://github.com/b0hemia/diskos/blob/main/docs/INSTALL.md), [Disco! v2.7.0 release](https://github.com/zmd22/diskos-disco/releases/tag/v2.7.0), [Disco! README](https://github.com/zmd22/diskos-disco), [QEMU status](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/emulator/docs/status.md), [QEMU profile policy](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/firmware/docs/firmware-profiles.md).

**Disco! 2.7.0 is a custom UI version, not FiiO stock V2.70.** The [release notes](https://github.com/zmd22/diskos-disco/blob/main/docs/releases/v2.7.0.md) add built-in Disc Shelf (Navidrome / experimental SMB3), download-and-cancel behavior, Shuffle! hold gesture and temporary Wi-Fi power-save handling. Those are candidate M3-08 scenarios. Upstream network/physical observations are not Lab runs: no stock `mq_player`, network, user credentials, external Disco! ELF or device acceptance was executed here. The [Reddit announcement](https://www.reddit.com/r/snowsky/comments/1xcwvrt/disco_270_less_cable_more_music/) is a discussion reference, not a trust anchor. A release tag must be resolved to an exact reviewed commit and output fingerprint before testing.

### New source-only candidate inventory (observed 2026-10-25)

| Community UI candidate | Upstream release | Resolved commit | Lab compatibility |
| --- | --- | --- | --- |
| diskOS | [v1.2.2](https://github.com/b0hemia/diskos/releases/tag/v1.2.2) | `66af1f639fd7c4adbb15f5b605100c3fd5733b8a` | **NOT RUN / candidate only** |
| Disco! | [v3.0.0](https://github.com/zmd22/diskos-disco/releases/tag/v3.0.0) | `721e07ee2266466888d84b92e756fd3a4fc778b1` | **NOT RUN / candidate only** |

These versions are newer than the existing reviewed baseline, **not replacements for immutable `upstreams.lock.yaml`**. Neither physical-device suitability nor emulator/SDK/update-package compatibility has been established by Lab. See [Community Platform Vision](COMMUNITY-PLATFORM-VISION.md).

## 3. Profile record and safeguards

Each firmware profile must be **reviewed before executable use** and reference the original published source when possible, including:

- Product, device model and hardware revision (do not assume related SNOWSKY devices share firmware).
- Main OS version, recovery OS version, OTA route and source archive provenance.
- SHA-256 of original ZIP/package and decrypted rootfs; encrypted chunk count, sizes and manifest integrity.
- Stock `mq_player`, `mq_ui`, loader, libc, tinyalsa and other critical ELF hashes, with MIPS architecture/endian/float ABI.
- Verified per-build patch anchors, absolute offsets, original bytes, ELF load mapping, allowed replacement bytes and already-patched checks.
- Emulated hardware capabilities and IPC protocol variants with independently verified behavior.
- Supported QEMU runtime and adapter pins, exposed/blocked scenarios and reasons.
- Disclosure of vendor-signature validation coverage. SHA-256 checksum equality alone is not automatically proof of vendor origin.

**Any hash mismatch must stop setup before running firmware.** An unknown firmware cannot borrow the nearest profile by numerical comparison such as `>= 2.57`. Memory writes and patches need exact binary fingerprint + expected original bytes.

Preserve an inventory record separately from an executable runtime profile; writing `inventory/v260.json` should never activate V2.60 support.

### Suggested profile design (not implemented)

```yaml
apiVersion: lab-firmware/v1
device: snowsky-disc
firmware:
  main: "2.57"
  recovery: "18"
  rootfsSha256: "<verified expected hash>"
  playerSha256: "<verified expected hash>"
runtime:
  runnerId: "<approved runner/commit>"
  patchProfile: "<reviewed identity or none>"
tests:
  required: ["boot", "touch", "library", "pcm", "restart"]
support:
  state: unknown   # only evidence-driven promotion changes this
```

Real values must be sourced from reviewed inputs rather than made up. YAML is an illustrative schema sketch and does not itself validate compatibility.

## 4. Capability-based compatibility

Represent specific features per version instead of one `supports_all=true` flag. Initial candidates:

| Capability | Example acceptance |
| --- | --- |
| `framebuffer-360` | Fresh 360x360 frame after UI launch, checked format/rotation |
| `input-touch` | Real tap, swipe, cancel path produces expected UI transition |
| `physical-keys` | Verified mapped key input/hold/repeat events |
| `mqueue-player` | UI receives state and sends play/pause/volume/next with observed player effects |
| `library-scan` | Fresh SD insertion or manual scan indexes generated fixtures correctly |
| `pcm-local` | Complete generated track yields sample-checked PCM, not merely silent output |
| `playlist-queue` | Enqueue, next, end-of-queue and restart cases observed |
| `artwork-render` | Correct display with local generated art and absent-art fallback |
| `power-lifecycle` | Guest-side sleep/stop/restart, persistent state and no process leakage |
| `radio-network` | Simulated network and protocol checks; **not** real Wi-Fi/BT hardware proof |
| `signed-ui-update` | Device-only, separately approved and witnessed, with matching enrolled signing keys |

Future feature/app compatibility must additionally bind the UI host/extension API or service contract, exact extension/build hashes, permissions, dependency graph and scenarios. A `full-ui`, statically integrated `ui-extension` and separately supervised `service-app` are not interchangeable; support is conditional on actual host integration rather than the module's self-declared compatibility.

Use `unsupported` or `blocked` for missing emulator hardware, not artificial successes. Do not require vendor functions absent by design if a tested UI explicitly excludes them, but document that exclusion prominently.

## 5. Isolation and historical compatibility

Each known-good version has its own:
- immutable firmware input identity/rootfs checksum;
- pinned QEMU runner/toolchain and per-version shim/patch review;
- isolated config/SD data/work volume with descriptive content identifiers;
- tests and baseline evidence;
- acceptance state and known limitations.

A new default may be published **without deleting or reinterpreting** an older supported runner. If the newest QEMU no longer runs V2.40, select a retained runner for V2.40 and keep the same CLI surface. A cached older version can become `stale` if no longer maintained, but historical evidence must not be represented as a test of newer changes.

## 6. New FiiO firmware detection workflow

The upstream [QEMU OTA research](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/firmware/docs/ota.md) documents a daily metadata poll and a **source-version → target-version** OTA map. The observed service may return a non-strict trailing comma and separate main/recovery versions. Our future monitor should:

1. Fetch **metadata only**, with bounded response, HTTPS checking, timeout and error reporting.
2. Validate full catalog structure/fields; accept only the explicitly reviewed vendor format deviations, never eval arbitrary text.
3. Compare known routes, main target **and** recovery version. New main or recovery changes open a deduplicated research issue; lack of a source route means **unknown**, not "no update".
4. Associate candidate with a documented source URL/reference and a new unique candidate record. Never mutate an accepted firmware profile.
5. If authorized and safely obtainable, verify the firmware package/chunks and vendor signature if a trusted verification procedure exists. Keep firmware and URLs/tokens out of public logs.
6. Produce static diff: ELF hashes, new libraries/ABI, IPC strings/handlers, init, device paths, patch anchors, changed features.
7. Run an independent candidate runtime in a fresh volume **only under a trusted, explicitly authorized environment**.
8. Compare defined acceptance suite and existing versions affected by runtime changes.
9. Open a reviewed support PR and record exact acceptance evidence. Promote only with complete scoped gates; old versions remain available.

**Outage/malformed catalog/403/hash mismatch** must produce `error` or `blocked`, never `no update` or `supported`. OTA monitoring is not unattended firmware acquisition/installation.

Upstream's current single-active-firmware policy is intentionally **not inherited** by our registry; that difference carries a permanent testing and maintenance cost.

For end-to-end future vendor update detection, all **registered/opt-in** UI compatibility checks, and distinct Lab versus physical-device update paths, see [Update Manager design](UPDATE_MANAGER.md). **Unregistered forks are not automatically run or implied compatible**. New vendor firmware must first pass a trusted stock runtime baseline; later UI compatibility is assessed separately.

## 7. UI fork intake and reporting

A community UI can enter via:
- **Binary mode:** supply a locally compiled `mq_ui`; inspect SHA/ELF/profile, then opt into a vetted runtime test.
- **Source mode:** immutable Git repository/revision + `lab-ui/v1` manifest + approved build preset; source is not automatically trusted.

Build/review and firmware/runtime stages have separate trust boundaries. A manifest compatibility claim does not bypass actual matching firmware/UI tests.

A report should include:
- UI author/project/revision and license;
- accepted/rejected artifact hashes and manifest/API version;
- firmware main/recovery/rootfs/stock-player identity;
- selected runner, patch and adapter revision;
- scenario table with pass/fail/not run/unsupported;
- timestamp, host environment, source provenance, log/screenshot/PCM artifact hashes;
- known limitations, expected vs observed behavior and reporter;
- clear `lab-run` vs `upstream` provenance.

Example report shape (illustrative, NOT results):

```text
Device: SNOWSKY DISC
Stock: V2.57, exact verified firmware hash
UI: external-fork @ <commit> / mq_ui sha256 <hash>
Runtime: QEMU runner @ <commit>
State: PARTIAL (not hardware verified)
  ELF check                  PASS
  Framebuffer ready          PASS
  Touch/navigation           PASS
  Playback PCM check         NOT RUN
  Restart                    NOT RUN
Source: locally collected Lab evidence, attach nonproprietary files only
```

## 8. Security/CI requirements

Public or fork PR jobs may run **firmware-free**, nonprivileged checks: docs/schema, parsing, synthetic POSIX mqueue, mock framebuffer, visual fixture, ABI inspection, build preset validation. They must not receive proprietary firmware, physical USB, secrets, privileged container entrypoints or maintainer SSH material.

Firmware-backed integration is a separate *trusted*, opt-in local or manually dispatched path after a maintainer reviews its code and input hashes. The QEMU user's host kernel exposure means privileged Docker must not be treated as a safe sandbox for arbitrary code. No `pull_request_target`/fork-triggered privileged firmware jobs.

Trusted firmware reports should allowlist exported artifacts. Screenshots of user's music collection, private keys, vendor rootfs/binaries and personal logs must not be published by default.

## 9. Physical testing and update safety

- Emulator `verified-emulator` status is deliberately separate from hardware.
- Hardware acceptance includes actual screen/animation timing, memory behavior, USB/BT/analog outputs, power drain and resume/cold boot on the stated hardware.
- Initial flash is a potentially destructive operation; do not automate it or expose as default test mode.
- A diskOS restore rootfs prepared from stock package is **not equivalent** to a comprehensive NAND dump of a specific user's device.
- UI-only signed SD updates after a valid initial install are preferable for iteration where supported, using pre-enrolled signing keys. Never replace the kept `mq_ui` file over SSH or leak keys.
- Device recoverability depends on verified procedures and intact inputs; do not guarantee recovery.

See [roadmap](ROADMAP.md), [architecture](ARCHITECTURE.md), and upstream [QEMU firmware porting](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/firmware/docs/porting.md).
