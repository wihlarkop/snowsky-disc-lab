# Technical Stack Decision — SNOWSKY DISC Lab

**Status:** Accepted for initial M0 implementation (2026-10-19). This is a design/implementation decision, not a claim that dependencies are already installed or tests have run.

## Decision summary

Build **SNOWSKY DISC Lab** as a local-first, community-friendly emulator development platform, not a server/SaaS. Preserve QEMU's MIPS CPU emulation and improve the workflows around it. **Sorane** is an independent custom UI project consuming the same external UI contract as any fork.

| Responsibility | Chosen technology | Start milestone |
| --- | --- | --- |
| CLI, source/firmware orchestration, adapters and reports | **Python 3.12+**, **Typer**, **Rich** | M0 |
| Typed data model, settings, input constraints and manifests | **Pydantic v2**; published JSON Schema for public contracts | M0 |
| Python dependencies and virtual environments | **uv**, `pyproject.toml`, committed `uv.lock` | M0 |
| Python lint/format | **Ruff** | M0 |
| Python static type checking | **Astral ty** (`ty check`) | M0 |
| Python tests | **pytest** (focused contracts, integration/regression first) | M0 |
| MIPS32 little-endian CPU execution | **Pinned upstream QEMU TCG user-mode** | M1 |
| Emulator hardware / native shims | **C**, selected version-pinned patches/overlays to upstream | M1–M3 |
| UI binary target / local previews | **C + LVGL 9.2.2 as vendored/pinned by upstream UI** | M2–M6 |
| Cross compilation | **Pinned MIPS32r2 / FP64 / NaN2008 musl GCC** compatible with UI build | M2–M3 |
| Local runtime | **Docker Engine + Compose** on Linux; **WSL2 + Docker** targeted on Windows 11 | M1 |
| Human-readable config / registries | **YAML + JSON Schema**, exact source hashes | M0–M5 |
| Test evidence | **JSON / Markdown**; SQLite only if persistent querying becomes necessary | M5 |
| Developer Studio (optional later) | **Svelte 5 + TypeScript + Vite**, **Bun**, **Oxc (oxlint/oxfmt)**, Tailwind CSS | Later |
| Studio-to-core boundary (if needed) | **FastAPI + SSE/WebSocket**; do not build an API server for CLI MVP | Later |
| Continuous integration | **GitHub Actions**, firmware-free untrusted checks + separate trusted firmware runs | M0 |
| Desktop packaging (optional, after CLI/Studio validation) | Consider **Tauri**; do not commit until proven necessary | Later |

### Type checking is ty

Use **Astral ty** as the *only* Python static type checker. Integrate it via the uv development dependency group and CI. Example targets after bootstrapping (not yet available):

```sh
uv sync --dev
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run pytest
```

Use type annotations and strict Pydantic validation at trust boundaries. Reconcile evolving `ty` behavior through a pinned version in `uv.lock`; do not suppress type errors globally or skip affected modules silently. Avoid introducing overlapping type-check tooling.

## Why CPU QEMU, not a from-scratch GPU emulator?

The DISC executes **MIPS32** firmware, while developer PCs commonly execute x86-64/ARM64. QEMU's **TCG** translates guest CPU instructions for host CPU execution; moving this sequential instruction stream onto a GPU is not a practical first optimization. The upstream QEMU emulator already models key framebuffer/input/PCM/user-space execution paths. Keep this as the compatibility baseline while profiling it.

**Graphics performance is separate from CPU emulation:**

1. **Fast UI preview:** native LVGL host renderer and synthetic/mock player for quick Sorane and community fork iteration. Should not require stock firmware or full QEMU boot.
2. **Integration emulator:** QEMU executes actual MIPS `mq_ui` + stock `mq_player` for observed IPC, input, display and audio behavior.
3. **Viewer presentation:** improve frame capture, transport and browser rendering only after baseline measurements; optional GPU-accelerated composition via browser/WebGL/WebGPU does **not** accelerate MIPS execution or guarantee new guest frames.
4. **Real hardware:** measure true DISC UI FPS, touch responsiveness, CPU/RAM/thermal/battery behavior and USB/BT/DAC there—not via qemu-user.

Upstream reports that the viewer samples framebuffer at `STREAM_FPS=12` by default and notes typical QEMU-limited ~5–15 FPS. These are **upstream observations**, not Lab measurements or a reason to advertise a 60-FPS target. [Viewer documentation](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/viewer/docs/usage.md).

## Packaging and scope discipline

- Use **one Python project** for CLI/orchestration and one pinned QEMU runtime/runner per applicable firmware group; avoid premature microservices.
- Expose `disc-lab` via `[project.scripts]` and one explicit CLI tree. The first shipped commands should be **read-only** `doctor`, schema/manifest validation, and source-lock verification; defer emulator boot to M1.
- Use Typer for CLI surfaces, Rich for diagnostics. Keep business logic independent of Typer so integration tests call the underlying functions.
- Use Pydantic for models and JSON Schema generation; YAML is only an input format, parsed with a safe loader and validated against strict models. Forbid arbitrary code in manifests.
- Use standard library for subprocess, filesystem, hashing and Git invocation where sufficient. Reuse upstream firmware tools behind clear isolated wrappers instead of introducing novel firmware extraction code without independent validation.
- UI and QEMU dependencies are **not** imported as normal Python libraries; they are external pinned sources/build artifacts managed by a narrowly defined adapter contract.
- No PostgreSQL, Redis, message broker, authentication system or hosted service in the MVP.
- No Rust in initial core. Introduce a narrowly scoped Rust/C performance component only after reproducing a bottleneck that Python/native upstream tooling cannot solve.
- Frontend is **deferred**. When added, use Svelte 5 + TypeScript + Vite + Bun + Oxc. The studio must consume the same core capabilities as `disc-lab`, not duplicate orchestration or bypass safety checks.
- Windows is a development target; WSL2/Docker compatibility and resource requirements need **actual** validation, not assumed success.

## Test and security approach

1. **Firmware-free M0:** schema validation, source lock, CLI `doctor` read-only behavior, good/bad manifest examples, deterministic diagnostic messages and safe path handling.
2. **M1 stock emulator:** trusted official FiiO firmware intake and exact fingerprint checks; boot, touch, SD indexing, byte-verified PCM and process lifecycle; preserve local artifacts only.
3. **M2–M3 external UIs:** source/binary verification; build sandbox separate from privileged trusted emulator runner; IPC, framebuffer, gesture, playback and restart regressions.
4. **Multi-version matrix:** per firmware **and exact runner/UI hashes** with `PASS`/`FAIL`/`NOT RUN`/`UNSUPPORTED`, no automatic cross-version inheritance.
5. **Performance:** instrument UI frame issuance, server capture/encoding, transport and browser paint independently; avoid calling host-QEMU timings hardware accurate.

**Public PRs and forks must not receive proprietary firmware, signing keys, credentials, USB host access or privileged Docker runtime.** No automatic device flash. No vendor rootfs/binaries in Git or CI artifacts.

## ADR/checkpoint guidance for Codex

This decision supersedes any earlier **proposed** stack description. While implementing M0:

- Prefer concise and conventional Python packaging, keep dependencies lean and **pin versions** with uv.
- Write code and focused tests only for requested M0 tasks; don't scaffold incomplete firmware/QEMU/player/desktop services merely to match a future architecture diagram.
- Add `ty check` and Ruff/pytest to local verification and GitHub Actions firmware-free jobs.
- Document real verification outputs and remaining `NOT RUN` status.
- Preserve existing roadmap, architecture, compatibility and contribution docs; update them only for verified progress or necessary decisions.
- Use feature branch + Draft PR for review; do not merge or alter protected/main branches without instruction.

## Future track: Developer Experience & Performance

After the first pinned V2.57 QEMU baseline and external `mq_ui` launcher work:

1. **Fast UI Preview**: native LVGL renderer + mock player, community fork templates, hot rebuild, UI snapshots.
2. **Integration Runtime**: safe UI handoff; input/PCM/IPC observability; version-specific profiles.
3. **Viewer profiling**: baseline stream capture FPS, encoding cost and end-to-end input-to-frame latency with reproducible measurements.
4. **Viewer optimizations**: event-driven frame capture, bounded transport, optional GPU-based browser composition **only if measured**.
5. **Developer Studio**: Svelte UI for firmware/UI version selection, run controls, screenshots, replay, compatibility matrix and reports.

Keep `Fast Preview` distinct from `Full QEMU Integration`; do not advertise host renderer screenshots as firmware-backed acceptance.

## References

- [Project roadmap](ROADMAP.md)
- [Architecture](ARCHITECTURE.md)
- [Compatibility contract](COMPATIBILITY.md)
- [QEMU viewer](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/viewer/docs/usage.md)
- [QEMU limits](https://github.com/eudj1n/snowsky-disc-qemu/blob/2.x/emulator/docs/limits.md)
- [Disco! UI development workflow](https://github.com/zmd22/diskos-disco/blob/main/docs/DEV_WORKFLOW.md)
