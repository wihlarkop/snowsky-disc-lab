# SNOWSKY DISC Lab

**A proposed community development, emulation, and compatibility lab for the FiiO / SNOWSKY DISC.**

> **Project status: planning / documentation only.** This repository does not yet contain a working emulator, CLI, adapter SDK, verified compatibility results, or a flashing tool. Commands below are targets, **not runnable instructions**. Do not interpret upstream test results as tests performed by this repository.

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
| [Compatibility & validation policy](docs/COMPATIBILITY.md) | Firmware profiles, support states, CI matrix, OTA intake and evidence rules |
| [Contributing](CONTRIBUTING.md) | How community developers can eventually add UI forks, firmware evidence and emulator fixes |

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

**Nothing has been validated by SNOWSKY DISC Lab yet.** The table summarizes *upstream evidence as of 2026-10-19* to determine initial work, not a promise about our runtime.

| FiiO stock firmware | diskOS 1.2.1 installer | Disco! 2.5.6 | Upstream QEMU stock runtime | Lab validation |
| --- | --- | --- | --- | --- |
| V2.09 | Listed by diskOS | Not an officially supported Disco! base | No reviewed profile | Not run |
| V2.28 | Listed by diskOS | Not an officially supported Disco! base | No reviewed profile | Not run |
| V2.40 | Listed by diskOS | Not an officially supported Disco! base | Historical profile / preview experiment | Not run |
| V2.57 | Listed by diskOS | Supported base per Disco! documentation | Active reviewed firmware | Not run |
| Newer / unknown | Unknown until reviewed | Unknown until reviewed | Unknown until ported | Not run |

Upstream details: [diskOS install](https://github.com/b0hemia/diskos/blob/main/docs/INSTALL.md), [Disco! README](https://github.com/zmd22/diskos-disco), [QEMU firmware profiles](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/firmware/docs/firmware-profiles.md), [QEMU limits](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/emulator/docs/limits.md).

## Planned developer experience (not implemented)

```sh
disc-lab doctor
disc-lab firmware inventory --version 2.57 --archive /path/to/official.zip
disc-lab ui build --source /path/to/my-ui --ref <immutable-commit>
disc-lab run --firmware 2.57 --ui /path/to/mq_ui
disc-lab test --firmware 2.57 --ui /path/to/mq_ui --suite ui-smoke
disc-lab compatibility report
```

External Git sources will require an explicit immutable ref, safe checkout, reviewable build recipe, and appropriate trust separation. Local binaries can be inspected without executing them first.

## Non-goals and safety

- **Not** a full-system, cycle-accurate, NAND/USB/Bluetooth/real-DAC hardware emulator. Current upstream uses **QEMU user mode** and substitutes many interfaces.
- **Not** a promise that any binary or UI fork will boot with every firmware.
- **Not** a firmware redistributor. Do **not** commit vendor ZIPs, decrypted rootfs, stock executables, generated firmware images, signing private keys, device data or secrets.
- **Not** an automated flasher. No background or CI process may write to a real DISC. Hardware deployment, if added, requires a separate explicit approval, validated prerequisites, recoverability plan and physical-device testing.
- **Not** permission to execute untrusted third-party builds inside a privileged firmware/QEMU environment. Public PR checks must not be given proprietary firmware, secrets or host device access.
- **Not** a replacement for physical performance measurements. QEMU responsiveness, CPU and memory metrics do not establish X2000 timing, battery use, or real-device frame rate.

**Trademark notice:** this is an independent community project and is not affiliated with FiiO, SNOWSKY, Ingenic, or the upstream maintainers.

## Immediate next step

Implement **M0** from the [roadmap](docs/ROADMAP.md): repository scaffolding, pinned dependency manifest, the versioned UI adapter contract, firmware-free checks and a safe `doctor` command. The first firmware runtime target is **stock V2.57**; older versions follow as separate reviewed profiles, never by silently reusing V2.57 binary addresses.
