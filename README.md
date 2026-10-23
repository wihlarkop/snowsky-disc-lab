# SNOWSKY DISC Lab

**A local-first, open development lab for SNOWSKY DISC firmware research, QEMU emulation, external UIs, and evidence-backed compatibility testing.**

> **Current status (2026-10-23): firmware-free foundations work; no stock firmware/UI combination is Lab-verified.** The pinned QEMU runner has executed first-party MIPS32LE synthetic guests, including input-to-framebuffer acceptance. Official FiiO `mq_ui` + `mq_player` V2.57, diskOS, Disco!, and physical DISC hardware have **NOT RUN** in the Lab. A source or ZIP being available is not compatibility evidence.

**[Roadmap](docs/ROADMAP.md) · [Compatibility policy](docs/COMPATIBILITY.md) · [Architecture](docs/ARCHITECTURE.md) · [Contributing](CONTRIBUTING.md)**

## What works today

| Area | Implemented | Boundary |
| --- | --- | --- |
| Host and source setup (M0) | `disc-lab doctor`, manifest validation, pinned `sources list/sync/verify`, public contracts and Linux/Windows firmware-free CI | Diagnostics do not prove QEMU or hardware readiness |
| Pinned QEMU + synthetic runtime (M1/M2) | Reviewed firmware-free build, identical clean repeat-build evidence, MIPS32LE guest execution, IPC/lifecycle tests, and six synthetic UI sessions with verified 16×8 RGBA frames | **Synthetic only**; not stock V2.57 or a 360×360 device framebuffer |
| Firmware preparation (M1-02/03) | Read-only structural ZIP/package inspection, private bounded snapshots, synthetic workspace lifecycle and receipts | Vendor authenticity, decryption, extraction and real firmware execution are **not authorized/verified** |
| External UI inspection (M2) | Offline ELF/MIPS ABI inspection, bounded local or exact pinned Git source inspection, source/build identity contracts, capability declarations | No third-party auto-build, stock player handoff or external UI launch |
| Compatibility evidence (M5) | Exact-identity registry, `compat list/show/compare/report`, versioned evidence and fail-closed diagnostics | No automatic `verified-emulator` or `verified-device` promotion |

See [synthetic UI acceptance](docs/M2-06-SYNTHETIC-UI-ACCEPTANCE.md), [firmware intake boundaries](docs/FIRMWARE-INTAKE.md), [source mode](docs/M2-SOURCE-MODE.md), and [registry documentation](docs/M5-COMPATIBILITY-REGISTRY.md).

## Firmware version support matrix

**Lab support means a particular firmware + stock player + QEMU runner + adapter + UI artifact has passed the required tests with exact hashes.** That has **not happened for any stock version**. `NOT RUN` means untested, **not** incompatible. `Candidate` means research/backlog only, **not** an accepted firmware profile.

| FiiO firmware candidate | Lab roadmap | Profile/preparation evidence | Stock QEMU | External UI in Lab |
| --- | --- | --- | --- | --- |
| **V2.57** | **Primary — M1/M2/M3** | Reviewed upstream profile; structural intake policy; firmware-free QEMU acceptance | **NOT RUN** | **NOT RUN** |
| **V2.40** | Historical — M4-01 | Historical upstream runner/preview only; no Lab stock retest | NOT RUN | NOT RUN |
| **V2.28** | Planned — M4-02/03 | New identity, profile and patch review required | NOT RUN | NOT RUN |
| **V2.09** | Planned — M4-04 | New identity, profile and patch review required | NOT RUN | NOT RUN |
| V2.21 | Candidate — later M4 | No reviewed Lab runtime profile | NOT RUN | NOT RUN |
| V1.95 | Candidate — later M4 | No reviewed Lab runtime profile | NOT RUN | NOT RUN |
| V1.86 | Candidate — later M4 | No reviewed Lab runtime profile | NOT RUN | NOT RUN |
| V1.77 | Candidate — later M4 | No reviewed Lab runtime profile | NOT RUN | NOT RUN |
| V1.76 | Candidate — later M4 | No reviewed Lab runtime profile | NOT RUN | NOT RUN |
| V1.65 | Candidate — later M4 | No reviewed Lab runtime profile | NOT RUN | NOT RUN |
| V1.56 | Candidate — later M4 | No reviewed Lab runtime profile | NOT RUN | NOT RUN |

These are **version candidates, not verified package identities**. Locally downloaded ZIPs still require private hash/provenance review and a new explicit acceptance record for each exact version. No vendor firmware files, rootfs images, or stock executables belong in this repository. See the [support-state definitions](docs/COMPATIBILITY.md#1-what-does-supported-mean) and [M4 roadmap](docs/ROADMAP.md#m4--multi-firmware-support-without-regressions).

### UI compatibility is separate from firmware compatibility

| UI candidate | Upstream information | Lab status |
| --- | --- | --- |
| FiiO stock `mq_ui` + `mq_player` | V2.57 is the first stock baseline target | **NOT RUN / UNVERIFIED** |
| [diskOS](https://github.com/b0hemia/diskos) | Custom UI/install project; several stock firmware bases documented upstream | **NOT RUN / UNVERIFIED** |
| [diskOS Disco!](https://github.com/zmd22/diskos-disco) | **[v2.7.0](https://github.com/zmd22/diskos-disco/releases/tag/v2.7.0)** released 2026-10-22; upstream first-install baseline remains FiiO V2.57 | **NOT RUN / UNVERIFIED** |
| Sorane | Planned separate UI repository using the public adapter | **Not implemented** |
| Community forks | Explicitly pinned source or binary, independently reviewed | **No Lab-verified combinations** |

**Disco! 2.7.0 is a UI release, not FiiO stock firmware V2.70.** Its new [Disc Shelf](https://github.com/zmd22/diskos-disco/blob/main/docs/releases/v2.7.0.md) integrates Navidrome/SMB3 downloads, menu-hold Shuffle!, and bounded on-demand network activity. SMB3 remains experimental according to upstream. Those features are **future M3 acceptance scenarios**, not features verified in this Lab. [Community announcement/discussion](https://www.reddit.com/r/snowsky/comments/1xcwvrt/disco_270_less_cable_more_music/) is a reference for follow-up, not test evidence.

## Getting started (firmware-free)

Requires **Python 3.12+** and [uv](https://docs.astral.sh/uv/). From a clean clone:

```sh
uv sync --locked --dev
uv run disc-lab --help
uv run disc-lab doctor
uv run disc-lab ui validate examples/ui-valid.yaml
uv run disc-lab ui inspect /path/to/local/mq_ui --format json
uv run disc-lab firmware validate examples/firmware-valid.yaml
uv run disc-lab sources list
uv run disc-lab sources sync
uv run disc-lab sources verify
```

`ui inspect` reads ELF metadata without running the file. Source-mode inspection/build-plan validation currently exposes a Python API rather than `disc-lab ui build`. Source sync fetches *reviewed, pinned public source projections*, not proprietary firmware.

To inspect a **locally obtained** firmware candidate without extraction:

```sh
uv run disc-lab firmware inspect /private/path/to/official-v257.zip --format json
```

Structural acceptance is **not** authentication, permission to decrypt, or a stock-QEMU readiness gate; a real vendor package may also be refused by the current intentionally narrow format policy. Keep its ZIP and receipts private. [Details](docs/FIRMWARE-INTAKE.md).

To read an existing **local** versioned compatibility registry:

```sh
uv run disc-lab compat list /private/path/to/registry.json --format markdown
uv run disc-lab compat show /private/path/to/registry.json --id RECORD_ID --format json
```

These commands do not download, discover, mutate, or verify external firmware or UI combinations. [Registry schema and rules](docs/M5-COMPATIBILITY-REGISTRY.md).

Developer checks:

```sh
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run pytest
```

Firmware-free CI covers Ubuntu and Windows on Python 3.12/3.14. Docker/WSL2 **stock firmware** isolation and local runtime acceptance remain a separate M1-07 gate.

## Roadmap at a glance

| Milestone | Status | Next major gate |
| --- | --- | --- |
| **M0** Foundation, source locks, schemas, CLI and CI | **Foundation complete** | Maintain regression coverage |
| **M1** Stock V2.57 in QEMU | Partial | Lawful intake/provenance, trusted isolation, stock boot, input, media and PCM |
| **M2** Generic external UI adapter | Partial | Stock player integration and public `run/test` lifecycle |
| **M3** diskOS + Disco! | Not yet integrated | Pin and test exact Disco! v2.7.0 and diskOS builds after M1 |
| **M4** Multi-firmware | Not yet validated | Independent profiles and stock acceptance for older versions |
| **M5** Registry and compatibility evidence | Partial | Trusted evidence assessment and remaining diagnostics |
| **M6–M10** SDK/Sorane, update detection, release, hardware, community | Planned/foundations only | See [detailed roadmap](docs/ROADMAP.md) |

## Upstream, licensing and trust boundaries

We build around **reviewed, immutable revisions** of [diskOS](https://github.com/b0hemia/diskos), [Disco!](https://github.com/zmd22/diskos-disco) and [snowsky-disc-qemu](https://github.com/eudj1n/snowsky-disc-qemu), not a blanket vendor of upstream repositories. New release announcements are **candidates** until source, dependencies, rights and exact outputs are reviewed. UI derivative code and assets retain their respective licenses; Sorane will be separate from the Lab core.

The Lab is **not** a firmware redistributor, device flasher, full-system emulator, or guarantee of physical-device safety. Never commit FiiO archives/decrypted rootfs/stock ELFs, private credentials, keys or personal media. Untrusted public PRs must not receive proprietary firmware, secrets, host USB, or privileged Docker. Emulated frames and timings do not prove real X2000 screen, DAC, Bluetooth or battery behavior.

This is an **independent community project**, not affiliated with FiiO, SNOWSKY, Ingenic or upstream maintainers. See [trust boundaries](docs/TRUST-BOUNDARIES.md), [compatibility](docs/COMPATIBILITY.md), [technical stack](docs/TECH_STACK.md), and [roadmap](docs/ROADMAP.md).
