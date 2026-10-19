# M0-04 / M0-07 verification

This stacked change starts from PR #3 at `9025c2e4c6ca46a075ccfed7e95aa7e2bfdd914a`; its Draft PR targets `codex/m0-source-cache`. The PR head identifies the implementation revision. No source pin, projection fingerprint, cache layout, dependency or package-lock change is included.

## Verified on Windows x86-64

- `uv sync --locked --dev`: PASS, existing 27-package environment unchanged.
- `uv run ruff check .`, `uv run ruff format --check .`, `uv run ty check`: PASS.
- `uv run pytest`: **142 passed, 1 skipped** (existing POSIX FIFO test on Windows). Git fixture tests need process permission outside the Windows helper-process sandbox. Default doctor, CLI opt-in wiring, metadata-only path checks, simulated Windows/WSL1/WSL2/native Linux, old/unparseable versions, unsupported hosts/architectures, low disk, unsafe/file cache paths and literal terminal output are covered.
- Real `uv run disc-lab doctor --help` and default `doctor`: PASS, exit 0. Actual observations included native Windows x86-64, Python/Git/uv and Docker/Compose/WSL component versions, cache location and disk metadata. Engine, edition/WSL runtime, actual ACL/write capacity, source integrity and QEMU readiness remained NOT VERIFIED. No daemon contact was requested.
- All three existing source caches passed the source manager's offline verification after the changes. All **40 raw evidence hashes** in the **21-row** initial license inventory matched those pinned cached files. No cache was replaced, repaired or migrated.
- Initial inventory uses component-level SPDX expressions with pending `NOASSERTION` rows. Review corrected DejaVu to Bitstream-Vera and preserved FreeType's FTL-or-GPL choice/module exceptions. It distinguishes UI GPL, integration/tooling MIT, external QEMU distribution and asset/license unknowns. No upstream notices were removed or Lab license chosen.

Tests do not require real cached upstream sources or firmware in public CI. The inventory's metadata test checks source identities/evidence URLs against the existing lock; preparation separately verified hashes locally. This is an initial evidence inventory, not an automated legal-clearance engine or exhaustive SBOM.

## CI and readiness boundaries

A one-time snapshot confirmed all four firmware-free PR #3 jobs (Windows/Linux, Python 3.12/3.14) passed at its pinned baseline: [run 39291223890](https://github.com/wihlarkop/snowsky-disc-lab/actions/runs/39291223890). That is not evidence for this new PR or a merged/integrated head. New CI completion is **NOT AWAITED** per the existing instruction.

Native Linux/WSL execution of the new preflight, real optional daemon contact, actual write/ACL probes, virtualization, container execution, upstream builds, QEMU, firmware-backed integration and physical-device acceptance: **NOT RUN**. No firmware was downloaded/extracted, no devices accessed, and no upstream scripts executed.

M0-04 and M0-07's baseline are complete. Full M0 closure still requires review/integration of the stacked changes and current CI evidence, plus **M0-08**. The smallest follow-up is a source-review-only external-UI handoff ADR covering stock player ownership, cold/warm startup, exact artifact/patch identities, isolated IPC/state, stop/failure behavior and the evidence required to evaluate warm-start adaptation. It should implement no runtime, patching or plugin SDK.

Toward M1, plan the exact runner/container/toolchain and local firmware/isolation gates after that ADR. Resolve component rights relevant to the planned build/distribution and obtain the owner's Lab LICENSE/NOTICE decision before packaged release. Host preflight and source pinning alone do not authorize or prove firmware/runtime compatibility.
