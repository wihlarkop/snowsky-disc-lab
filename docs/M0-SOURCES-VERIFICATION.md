# M0-02 / M0-05 verification

Implemented against the unmerged PR #2 head `67982764c2fa0585ef4d6a1c68616cba9e9da52a` as a stacked feature branch. The PR head identifies the final implementation revision; this document records the behavior tested locally on Windows x86-64, CPython 3.14.0 free-threaded and Git 2.45.1.windows.1.

## Verified locally

- `uv sync --locked --dev`: PASS; no new dependencies or dependency-lock changes.
- `uv run ruff check .`, `uv run ruff format --check .`, `uv run ty check`: PASS.
- `uv run pytest`: **107 passed, 1 skipped**. The skip is the existing POSIX FIFO manifest test on Windows; source symlink tests passed. Git-backed tests used elevated process access because the Windows sandbox blocks Git's local transport helper.
- `uv run disc-lab sources list`: PASS without fetching or creating a cache.
- `uv run disc-lab sources sync --source ID`: PASS for all three real locked GitHub pins, selecting only the reviewed source projections and verifying committed bytes and selected raw license SHA-256 checksums.
- `uv run disc-lab sources verify` and `uv run disc-lab sources sync --offline`: PASS for all three cached pins with transport protocols disabled during verification.
- Independent cache inspection: the excluded UI `flash/disc_spl_lpddr3.bin` Git objects are absent locally, as are `flash/` and `payload/` worktree directories. QEMU's `firmware/` worktree is absent. Materialized source files are read-only.

Synthetic Git integration covers wrong HEAD/remote, changed files hidden by assume-unchanged, missing selected Git objects, unsafe projection/cache paths, selected symlink refusal, existing-directory publication refusal, cache preservation and offline cache misses. Lock/CLI tests cover URL/provenance/version/schema errors and projection safety. Tests use synthetic content, including a fake excluded payload; no proprietary fixtures are committed. Initial upstream ref/tree/license review and independent focused code review were delegated to Luna; actionable findings were resolved.

An initial live QEMU attempt exposed an invalid Git status option, which was fixed. Its failed staging directory remains ignored and preserved for inspection. No cache was automatically repaired or deleted. All final live/offline commands passed after correction.

## Limits and next scope

This verifies source identity and a deliberate subset of each upstream tree, not a complete build checkout, source security certification or firmware compatibility. Tags are discovery metadata; see [provenance](UPSTREAM-PROVENANCE.md) for unsigned input limitations. Symlinks, recursive submodule/LFS intake and arbitrary hosting protocols are unsupported. Full SPDX/license inventory remains M0-07.

CI is configured for firmware-free Linux/Windows Python 3.12/3.14 checks and synthetic source tests. Hosted CI completion is **NOT AWAITED** as requested; native Linux publication, full upstream builds, QEMU/runtime, firmware-backed acceptance, WSL2/Docker runtime and physical devices are **NOT RUN locally**. No upstream code was executed, firmware acquired, physical device accessed, or flashing performed.

Recommended next scoped milestone: finish M0-04 host preflight and M0-07 trust/license gates before M1 stock V2.57 integration. No source verification result promotes runtime support.
