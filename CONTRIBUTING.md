# Contributing to SNOWSKY DISC Lab

Welcome! **SNOWSKY DISC Lab has an M0 firmware-free CLI and manifest contracts.** UI SDK, emulator integration and firmware releases remain future work. Start with the [README setup](README.md#runnable-m0-cli), [contracts](docs/CONTRACTS.md), [ROADMAP](docs/ROADMAP.md), [ARCHITECTURE](docs/ARCHITECTURE.md) and [COMPATIBILITY](docs/COMPATIBILITY.md). Contributions and feedback are welcome, but status claims must be backed by real test evidence.

This is an **independent SNOWSKY DISC-specific** project. Do not infer support for SNOWSKY Echo or other products from the shared brand.

## What can people contribute?

- **Documentation and research:** diagrams, clarification, independent upstream source references, reproduction notes and firmware inventories (metadata/hashes only).
- **Core/CLI:** safe dependency resolution, schema validation, source locks, error reporting, read-only `doctor`, report rendering.
- **Community UI adapters:** a versioned manifest, a pinned reproducible build recipe, ABI inspection and behavioral tests for a diskOS, Disco!, Sorane or unrelated UI fork.
- **Mock tools/tests:** fake player IPC, generated music/art fixtures, host-render screenshots and firmware-free CI regressions.
- **Trusted firmware compatibility research:** per-version evidence, clearly identifying the exact stock firmware and binary fingerprints, tested locally with user-obtained official firmware.
- **QEMU integration fixes:** narrowly scoped adapters or patches with exact pinned upstream revisions, documented independent validation and minimal interference with `mq_player`.

## First contribution workflow (proposed)

1. Check the [roadmap](docs/ROADMAP.md) for an open task or create an issue describing a reproducible need.
2. State the category: documentation, UI plugin, firmware profile, emulator/runner, security, or tests.
3. Keep PRs narrowly scoped. Include **what changed, why, how verified, and what was NOT tested**.
4. Preserve all upstream copyrights/licenses; keep source and generated binaries separable.
5. Use firmware-free checks for untrusted/public PRs. Never run someone's fork or PR scripts in a privileged firmware/QEMU container.
6. For compatibility claims, attach **nonproprietary** report data including exact commits, ELF/rootfs hashes as appropriate, tested scenario names and their results. Do not attach private firmware, vendor binaries, user music, keys or memory dumps.

### Suggested pull request checklist

```text
[ ] Target roadmap milestone / issue is linked
[ ] New files include license/third-party attribution where needed
[ ] Source and upstream revisions are pinned to exact immutable commits
[ ] New firmware checks fail closed on unknown/mismatched fingerprints
[ ] No vendor ZIP/rootfs/stock binary/device dump/signing key is committed
[ ] Firmware-free tests executed; report exact command + PASS/FAIL/NOT RUN
[ ] Firmware-backed tests run only in a reviewed trusted environment (if relevant)
[ ] Previous supported versions are not silently removed or overwritten
[ ] Device flashing is not triggered from build/test/release or CI
[ ] Compatibility claims and known limitations are updated accurately
```

## Fork developers: intended integration model

A fork developer **should not need to fork SNOWSKY DISC Lab itself**. The future `lab-ui/v1` contract will allow:
- locally compiled `mq_ui` (binary inspection and trusted opt-in run), or
- source checkout at an immutable commit plus a reviewed build preset/manifest.

Example manifest/commands are available in [architecture](docs/ARCHITECTURE.md); these are **design sketches and not yet executable**. A fork author's supported-firmware claim remains unverified until accepted by a reviewed Lab test run. Generic fixes to adapters/build preset contracts should be proposed to Lab; feature/design changes should stay in the fork's own repository.

We encourage independent themes and projects; no specific visual style or derivation from Disco! is required.

## Evidence for a firmware support issue

Please include *only metadata safe to share*:
- SNOWSKY DISC hardware/device revision where known;
- stock main OS and recovery version, and source/archive hash when lawful/appropriate;
- the exact pinned emulator, UI build and adapter revisions;
- host OS, Docker/WSL version and any relevant reproducible setup detail;
- exact failed command/scenario, sanitized output, expected vs observed behavior;
- whether the result was an emulator experiment or tested on a physical device.

Do not claim broad compatibility based on a successful menu screenshot, an archive filename or version comparison. Do not publish vendor firmware or proprietary blobs as a convenience for other contributors.

## Safety and disclosure

- **No automatic flashing:** Device writes require manual approval and a vetted, documented recovery plan outside ordinary CI.
- **No secret exposure:** Don't post OTA URLs containing credentials, signing private keys, GitHub tokens, personal files, MAC/calibration/device dumps or personally identifying debug logs.
- **No untrusted privileged tests:** QEMU user mode shares the Linux host/VM kernel. Privileged Docker and guest-provided files are not suitable execution environments for arbitrary public pull requests.
- **No workaround of version/hash refusals:** Unknown firmware gets a research candidate and independent review rather than disabled safety checks.
- **Responsible security reporting:** Before a dedicated private disclosure route is configured, avoid publicly posting exploit details or credentials. Request a private maintainer contact rather than filing a fully detailed public issue.

## Licenses and attribution

- [QEMU code](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/LICENSE) is MIT.
- [diskOS UI](https://github.com/b0hemia/diskos/blob/main/ui/README.md) and [Disco! UI](https://github.com/zmd22/diskos-disco/blob/main/ui/README.md) identify GPL-3.0-or-later obligations; their tooling/other components may have distinct licenses.
- Lab original core-code licensing is **not finalized until a LICENSE/NOTICE audit**. Do not simply relabel copied GPL or third-party code.
- Sorane will be a **separate UI repo** with its own source history and appropriate derivative licensing if based on diskOS/Disco!.
- The original FiiO firmware and generated rootfs image are not distributable project assets.

Thanks for keeping SNOWSKY DISC research reproducible, collaborative, and safe.
