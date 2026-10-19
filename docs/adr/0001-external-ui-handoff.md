# ADR 0001: External UI handoff and stock player ownership

**Date:** 2026-10-20. **Status:** proposed for review; selected initial design below, implementation deferred to M1/M2. **Scope:** M0-08, SNOWSKY DISC only.

This ADR records source observations separately from proposed Lab behavior. No firmware, emulator, upstream executable or hardware was run for this decision. Nothing here promotes a firmware/UI combination to Lab-verified. [Current contracts](../CONTRACTS.md), [compatibility policy](../COMPATIBILITY.md), [trust boundaries](../TRUST-BOUNDARIES.md) and [source locks](../../upstreams.lock.yaml) remain authoritative for implemented M0 behavior.

## Context and immutable evidence

The reviewed source identities are:

| Project | Exact commit | Role |
| --- | --- | --- |
| diskOS | `4cd4a60003944b0cf4e8e5fb9feac2d07ea87df9` | Current selected UI source; not the historical preview build |
| Disco! | `485fe0ff685b3c386e679491cda74e275016b481` | Current selected community UI source |
| Snowsky Disc QEMU | `85ab00deb08ac112066377fd8083cc8727ed859a` | Current runtime source and preserved historical experiment |
| Historical diskOS preview input | `85a327ca56af2676c850f24ddcba5f34135132d4` | Informational historical input identified by the experiment; not a new Lab dependency pin |

The three current source projections passed offline verification during this review. See [provenance](../UPSTREAM-PROVENANCE.md) for their projection boundaries and excluded payloads. Historical `experiments/diskos/` text was read separately at the exact QEMU commit, because experiments are excluded from the cache. This neither expands the projection nor fetches the historical UI binary. Immutable links below support source/document claims; upstream authors' recorded runtime observations were not reproduced here.

### Current QEMU source observations

| Concern | Verified in source/documentation at the pinned commit | Limit of the observation |
| --- | --- | --- |
| Direct cold boot | [`20_boot.sh`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/scripts/20_boot.sh) verifies firmware, stops the prior rootfs guest, resets board state, starts stock `mq_ui`, sleeps four seconds, then starts `mq_player`. UI creates the `ui` queue; backend pushes state. Default guest TTL is 1800 seconds. | A fixed delay is not a protocol-readiness guarantee. Direct mode supplies no crashed-pair restart loop. |
| Stock-init ownership | [`stock-init.md`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/docs/stock-init.md) describes optional `rcS → S98FIIO → fiio_init.sh`, its five-second watch loop and guest PID/IPC/UTS/time namespaces. [`guest_init.py`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/runtime/guest_init.py) reaps children and handles shutdown. `S98FIIO` has no stop action; clean shutdown runs `rcK`, then TERM/KILL. | Stock-init and Lab supervision must not compete over the same pair. Direct mode otherwise shares the container's PID/IPC view. |
| IPC | [`lib.sh`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/scripts/lib.sh) clears queue entries at board reset. Current [diskOS IPC source](https://github.com/b0hemia/diskos/blob/4cd4a60003944b0cf4e8e5fb9feac2d07ea87df9/ui/ipc.c) opens/creates `/ui`, opens `/player`, and detects queue replacement by identity to reopen descriptors. [Disco! IPC](https://github.com/zmd22/diskos-disco/blob/485fe0ff685b3c386e679491cda74e275016b481/ui/ipc.c) is a separately pinned implementation. | Named queues can outlive a UI; unlink/recreate can orphan open descriptors. They are not broadcast streams; a diagnostic consumer can steal messages. Neither current UI is established as compatible with this emulator. |
| Input/frame readiness | [`boot_ready.py`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/runtime/boot_ready.py) waits up to 60 seconds: `mq_ui` must hold touch `event1`, `mq_player` key `event0`, and that UI's namespace PID must match `emu/fb-flush`. | Names or old pixels alone do not count. Static direct framebuffer stores without a pan may lack an observable flush. Input handles/frame do not prove backend protocol or playback health. |
| Devices and ABI | Stock-init documentation describes regular-file framebuffer/input stubs, 360×360×32 framebuffer with three sub-buffers, dynamic `fbshim` preloading, and a rebuilt Debian QEMU 7.2 device patch for static-program ioctls. [`lib.sh`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/scripts/lib.sh) includes the hard-float/non-executable-stack guard. [`10_setup_env.sh`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/scripts/10_setup_env.sh) installs `fbshim`, `asndshim`, `tinyshim` and approved setup patches. | Static musl binaries bypass dynamic preload interposition. The static device patch does not provide static audio interposition. Emulator success can hide a device ABI failure. A source commit is not a built runner/toolchain digest. |
| Process identity | Stock-init docs explain `comm`, `argv[0]`, binfmt `P`, `PROC_EXE` and BusyBox `pgrep -x`: starting a program with a path as `argv[0]` can make the stock watch loop miss it and repeatedly restart the pair. | A process called `mq_ui` is not proof it is the expected binary or that it owns the devices. |
| Stop and shared resources | Rootfs-scoped `kill_guest` avoids killing every QEMU process. [`99_stop.sh`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/scripts/99_stop.sh) also uses a viewer-name `pkill`. Stock-init docs and `lib.sh` identify Docker-VM-wide binfmt registration and shared loop devices. | Do not reuse global viewer-name killing or assume separate Compose project names isolate kernel-global state. No concurrent-session isolation was tested by Lab. |

The presence of [`mqshim.c`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/shims/mqshim.c), which forces creation attributes, is not proof that it is loaded in every runtime; current setup's preload list is explicit. Any future queue workaround must be selected, pinned and tested, rather than inferred from a file's existence.

### Historical V2.40 warm-player preview

The pinned [`preview.md`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/experiments/diskos/docs/preview.md) describes a historical, unsupported preview captured on 2026-09-13: stock **V2.40**, diskOS **`85a327ca56af2676c850f24ddcba5f34135132d4`**, static musl UI, and an emulation-only framebuffer adapter. It is not the current diskOS lock or Disco! 2.5.6.

[`boot.sh`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/experiments/diskos/boot.sh) requires an isolated experiment and V2.40, boots stock first, kills only stock UI processes in that rootfs, leaves `mq_player` alive, installs the experiment UI under `/usr/data/mq_ui`, and launches with `DISKOS_EMU_WARM_PLAYER=1` and QEMU `-0 mq_ui`. The explicit `argv[0]` avoids the UI's normalization/re-exec loop. A `diskos reached main loop` log is used as a startup check; it is not a playback acceptance assertion.

[`prepare.py`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/experiments/diskos/prepare.py) checks an exact source anchor and changes the build copy's `v240_workmode_cb`: with the warm flag, delete the timer and return, skipping redundant route initialization after stock UI warmed the player. Without the flag, normal startup remains. [`emu_io.c`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/experiments/diskos/emu_io.c) wraps `ioctl` at link time, supplies framebuffer geometry and accepts the startup page-zero pan, publishing `/emu/fb-live`. That older adapter is not equivalent to current per-process `fb-flush` readiness. [`build.sh`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/experiments/diskos/build.sh) builds from the exact archived UI revision in a separate copy.

The author's controlled comparison records the unadapted route initialization stopping playback at **9.01 seconds** when `v2.40 workmode: local-init sent once` occurred. The warm adaptation produced **30.15 seconds including padding**, with the generated WAV waveform complete; no browser client was attached, ruling out browser audio reading in that comparison. The preview also records touch/library/SD scan/Cyrillic-path observations. A separate same-track reselection after reboot still stalled at about **five seconds**, while Play/Pause worked. Migration checks on 2026-09-17 rebuilt and captured the preview but did not repeat full playback, scan or power acceptance. Restart-menu behavior, V2.57 and hardware were unvalidated.

**Inference:** backend route state and queue lifetime make warm replacement a separate compatibility mode. These observations justify investigating it, but do not prove reliable recovery or authorize copying the callback change into V2.57/current UI sources.

## Decision: cold session first; defer warm replacement

Recommend **one Lab-owned cold session with one external UI and the stock backend**, after a reproducible stock V2.57 baseline. Initial M2 uses an explicit direct-start profile with no competing stock watch loop. It never first warms a player using stock UI and then silently switches. This is a proposed strategy requiring experiments; current UI cold-start compatibility is unknown. If it fails, report the combination blocked rather than implicitly trying warm mode or another firmware.

Preserve stock `mq_player` as the firmware backend. The session supervisor owns its lifetime and the selected UI's lifetime together. No UI-specific player patch is allowed. Any emulator-baseline patches already required for stock execution are separately reviewed, hashed and distinguished from original stock bytes. They are not an excuse to modify the player to accommodate a custom UI.

Warm mode is **deferred**. A later reviewed adapter may enable it only for an exact firmware/player/UI/runner/patch tuple with evidence of queue continuity, route state, playback, UI replacement and recovery. Stock-init adapters also remain separate: they must explicitly resolve watcher ownership before external replacement; killing a watched UI without that decision is refused. No public `auto` mode chooses an unverified strategy.

### Public adapter boundary (proposed, not a new M0 schema)

All UIs use `inspect`, optional `build`, `preflight`, `launch`, `stop`, `collect`, `report`. `preflight` returns a reviewed capability/launch plan or a structured refusal; it performs no launch. Preparation is an internal bounded phase of `launch`, not a second public `prepare` API. Source acquisition stays in the source manager, builds consume verified snapshots in a separate unprivileged workspace, and runtime orchestration stays in a firmware-version-specific adapter.

Future manifest-free binary inspection accepts a binary as a separate input mode. Supplying a `lab-ui/v1` manifest still requires all its current fields. Neither mode grants execution authority. Recipe IDs, firmware claims and names cannot select arbitrary scripts, privileges, environment or patches. Execution-plan fields below belong to a future reviewed adapter contract and require versioning/tests before implementation; do not add them to the current manifest implicitly.

diskOS, Disco!, Sorane and independent forks receive the same capability and refusal rules. UI-specific adaptations belong in pinned reviewed recipes/overlays with attribution, never private core imports or Sorane-only privileges. An unsupported capability reports `UNSUPPORTED`, not fabricated success.

### Exact execution identity required before launch

The approved plan and local evidence must bind all of:

- Device/profile schema and revision; exact main/recovery identity; original package and extracted rootfs SHA-256; provenance and actual signature/authenticity coverage, including what could not be verified.
- Original stock UI/player, loader/libc and relevant library hashes; final executed bytes after approved baseline overlays. Firmware labels such as V2.57 alone cannot select patches.
- QEMU integration commit, QEMU source revision and executable SHA-256, device patch bytes/hash, container image digest, compiler/sysroot/build recipe pins, and built shim hashes/load order. Record `QEMU_DEVICES`, `PROC_EXE`, ABI guard and boot/network mode explicitly.
- UI source commit where available, manifest/schema digest, build recipe/toolchain and dependencies, input ELF SHA-256/ABI/library report, any adaptation's source anchor/expected bytes and resulting ELF hash. A local binary without source provenance remains explicitly identified as such.
- Adapter code revision and plan version, patch input/output hashes and exact expected anchors, scenario/synthetic fixture hashes, host/kernel/VM/runtime versions, run ID and session ownership record.

Missing identities, unknown/changed bytes or stale evidence fail closed. Original and patched fingerprints are distinct; an already-patched or unexpected input is not patched again. **These runtime fingerprints have not been measured in Lab** and no placeholder hash is an approved value. Existing source locks do not pin firmware, built QEMU or UI executables. Preserve previously accepted tuples; updates are new candidates with independent state and regression review.

### Proposed lifecycle and deadlines

All durations below are initial **design budgets**, not measured compatibility guarantees. A reviewed versioned plan may change them with evidence; manifests cannot override them arbitrarily. Use monotonic deadlines and record elapsed time and failure stage. No unbounded retry loop.

| Phase | Required behavior | Initial deadline/failure |
| --- | --- | --- |
| Resolve and approve | Verify exact identities, authorization, ABI/dependencies/rights, allowed capabilities and exclusive runtime ownership before mutation. | Any missing/refused precondition blocks execution. |
| Prepare | Allocate a fresh owned work area from immutable stock inputs; private PID/IPC/mount/network view, framebuffer/input/PCM/logs and fresh control markers. Install only the approved UI overlay; no concurrent stock UI. | 60 s; failure tears down this session. Firmware extraction is a separate M1 operation. |
| Start UI | Spawn the exact inspected ELF through the approved interpreter with correct `argv[0]`; track PID plus start identity. Wait for `/ui` with expected attributes/ownership. Do not consume messages as a probe. | 15 s; never start backend against an absent/foreign queue. |
| Start backend | Start the exact stock `mq_player` once, after UI queue creation. Verify `/player`, both process identities/device holders and an adapter-defined non-destructive backend state observation. | Combined UI/backend readiness within 60 s of first spawn. |
| Ready | Require a new frame attributable to this UI instance, touch/key holders and valid backend IPC observation. Follow with a bounded input-to-frame smoke scenario. | Input smoke 10 s; a log, open port or old frame alone cannot pass. |
| Running | Supervise both processes, queue identities, frame/input and applicable backend progress; log explicit outcomes and bounded scenario deadlines. A quiet screen/paused audio is not itself a hang. | UI/player exit, unexpected pair restart or queue replacement fails the initial adapter session. No automatic in-place healing. |
| Stop | Stop accepting input; signal only owned processes, allow bounded TERM, then KILL survivors and reap. Stop backend even when UI already exited. | 5 s TERM, 5 s KILL/reap; inability to establish shutdown quarantines the work area. |
| Collect/close | Unmount/release only owned resources after process exit; preserve sanitized local evidence and immutable cache/base. No automatic public export. | 30 s cleanup budget; timeout records incomplete cleanup and blocks reuse. |

The UI-first ordering is based on upstream queue ownership, not a claim that any UI can safely boot cold. Exact queue attributes and backend-state predicate must be established by M1/M2 experiments; absent a reliable predicate the adapter is blocked, not ready after a sleep. In particular, current diskOS queue-reopen logic is useful source evidence, not proof of a stable cross-version protocol.

An explicit restart creates a new run ID and fresh volatile state, restarts **both** UI and player, and repeats readiness. Persistence is an explicitly selected versioned userdata snapshot, never accidental reuse of a failed run. Default M2 crash recovery records failure and stops the entire session. User-requested retry is a new cold run; no silent fallback to stock UI, alternate patches, or retained warm player. Initial playback continuity across UI crashes is not promised.

### IPC, framebuffer and session isolation

Queue names stay firmware-compatible (`/ui`, `/player`) inside a **private IPC namespace** with its own mqueue mount. Do not rename wire endpoints or unlink queues in a shared namespace. No second UI or diagnostic receiver drains the backend-to-UI queue. Detect unexpected queue inode/attribute replacement; initial M2 stops instead of reusing stale descriptors. Protocol observation must be non-consuming or an explicitly reviewed instrumentation layer.

Each session has its own framebuffer file, buffer/flush markers, input event stream, audio capture, virtual card, userdata and log paths. Reset volatile markers only before that session starts. Verify frame identity/generation, not just pixel content; static UIs without a reliable flush signal need reviewed instrumentation or are unsupported. Validate geometry, pixel format, buffer selection and touch coordinate behavior together. No host input/USB device mapping.

Use exact session process handles/start identities and a confined process tree, not global name matching. Container/project/run IDs and filesystem paths must agree. Reject attach-to-existing-player, ambiguous ownership, active stale mounts, unsafe links or paths, and shared mutable volumes. Check containment/no-follow at use and cleanup time; preserve interrupted evidence and quarantine ambiguous state under the [trust lifecycle policy](../TRUST-BOUNDARIES.md).

Binfmt registrations and loop devices can be VM-global. Initial runtime preparation must use a dedicated controlled VM/runtime boundary or an independently reviewed method that avoids modifying shared registrations. Serialize operations within that boundary until concurrent-session isolation is demonstrated. Refuse execution if unrelated sessions might be affected; do not stop them or replace their interpreter. Separate directories/Compose names alone are insufficient. qemu-user and privileged containers do not sandbox arbitrary binaries; reviewed trusted local execution remains separate from untrusted firmware-free builds.

## Alternatives and consequences

| Alternative | Benefit | Reason for decision |
| --- | --- | --- |
| Cold external UI + stock player under one session owner | Fresh IPC/state, explicit startup order, reproducible failure and restart | **Recommended initial M2 strategy**, contingent on stock baseline and cold-start validation. Some UIs may remain blocked. |
| Stock boot then warm UI replacement | Preserves initialized backend; historical V2.40 experiment demonstrates a narrow path | Deferred: hidden route/queue state, callback adaptation and unresolved restart stall; no V2.57 evidence. |
| Stock-init with an external UI boot overlay | Exercises real startup/hooks and stock watchdog behavior | Later separate adapter: competing supervisors, argv identity and pair respawn require explicit evidence and ownership. M1 can characterize stock-init without custom injection. |
| Edit/replace player or add per-UI emulator forks | Could work around a specific mismatch | Reject initial approach: loses the stock backend comparison and multiplies unsupported version-specific behavior. |
| Simulated player/native UI preview | Firmware-free and safer for untrusted development | Useful separate future path; cannot establish stock firmware or physical-device compatibility. |

This decision sacrifices warm playback continuity for a smaller initial lifecycle and truthful refusals. It does not rule out later exact-version warm adapters or stock-init integration, but each needs its own retained plan and evidence.

## Implementation sequence and acceptance boundaries

**M1 — stock V2.57 first.** Begin with runtime preparation: pin QEMU/build/image/shims and baseline patches, define lawful local firmware identity/authenticity checks and dedicated isolation/cleanup/export policy. Then implement safe local intake/extraction in separate reviewed work and establish a fresh-state stock direct boot with original UI/player. Verify queue/device/frame ownership, input response, generated-media indexing, complete PCM comparison, clean stop/restart and crash/timeout cleanup. Characterize optional stock-init/watch-loop and shared-kernel effects separately; mark modes not exercised as NOT RUN or unsupported. Preserve per-run evidence and hashes. Do not introduce custom UI execution to make a failing stock baseline green.

**M2 — reviewed external adapter.** After stock acceptance, version the execution plan and implement static ELF inspection, bounded lifecycle/refusal behavior and confined session ownership. Start with a tiny firmware-free synthetic UI/IPC fixture, including stale markers, queue replacement, missing backend, crash, timeout, restart and isolation tests. In a separately authorized trusted local run, validate the initial cold external adapter against the exact M1 baseline with generated media. Retain stock regression evidence. Concrete diskOS/Disco! presets and broad functional coverage remain M3; no current fork gains approval merely from a recognized preset name. Warm mode and earlier firmware remain separately gated future work.

**QEMU experiments still required:** cold UI queue timing/attributes; actual player protocol readiness; static framebuffer/touch/ABI behavior and shim ordering; route initialization and complete PCM; PID/argv/watch-loop behavior; stop/restart and queue orphaning; ownership under PID reuse; concurrent/failed-session isolation; kernel-global binfmt/loop effects. Sources and doctor cannot settle these.

**Block custom execution** for unknown firmware/binary/patch fingerprints, absent stock acceptance, missing authorization or component review relevant to the operation, unsupported ABI/device/protocol capability, untrusted executable in a privileged runtime, unresolved watcher ownership, stale/foreign queues or state, unsafe paths/mounts, shared-kernel interference, missing readiness predicate, or failed cleanup. Report the specific refusal; do not relax a gate to obtain a screenshot.

Emulator evidence is scoped to the exact tuple and scenario. Menu/input/IPC/PCM/restart results do not certify CPU timing, real DAC/Bluetooth/USB, suspend, battery, NAND, recovery or physical stability. `verified-device` requires separately authorized physical acceptance; no device operation is part of M0/M1/M2's emulator evidence.

## Review and follow-up

See [M0 integration readiness](../M0-INTEGRATION-READINESS.md) for stack order, current CI, unresolved release rights and closure gates. This ADR implements no launcher, QEMU runner, firmware intake/extraction, guest injection or plugin SDK. It selects no Lab license and clears no component rights.

**First M1 task: stock V2.57 QEMU runtime preparation.**
