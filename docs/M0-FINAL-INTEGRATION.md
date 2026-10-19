# M0 final integration candidate

Prepared 2026-10-20 on `codex/m0-final-integration`. This candidate combines the M0 stack with latest main without changing, retargeting, closing or merging the original Draft PRs. The integration PR's exact head and checks are the verification authority; earlier stack CI is historical evidence only.

## Inputs and history

| Input | Exact reviewed commit | Base at review |
| --- | --- | --- |
| Latest main | `a475db79c1b4c2c26557f39197de7e19cb04b3b2` | Main documentation updates |
| [PR #2](https://github.com/wihlarkop/snowsky-disc-lab/pull/2) | `67982764c2fa0585ef4d6a1c68616cba9e9da52a` | `main` |
| [PR #3](https://github.com/wihlarkop/snowsky-disc-lab/pull/3) | `9025c2e4c6ca46a075ccfed7e95aa7e2bfdd914a` | `codex/issue-1-m0-foundation` |
| [PR #4](https://github.com/wihlarkop/snowsky-disc-lab/pull/4) | `f91d20ee3f3c92266445637bf54c72c44635b03d` | `codex/m0-source-cache` |
| [PR #5](https://github.com/wihlarkop/snowsky-disc-lab/pull/5) | `ef619cb8e87f95007640ba3fdda6a2a31deb3e6a` | `codex/m0-preflight-trust` |

All four original PRs were open Drafts, with the complete Ubuntu/Windows Python 3.12/3.14 matrix successful at their respective heads. No submitted reviews, issue comments or inline review comments were present. This does not constitute maintainer approval.

The integration branch starts from main and merges PR #5's head with a merge commit. Its ancestry already contains the original PR #2 → #3 → #4 → #5 commits in order, so no cherry-picks or duplicate implementation commits are required. There were **no textual conflicts**. The automatically combined documentation was reviewed for semantic regressions rather than accepted by choosing one side wholesale.

## Preserved decisions and boundaries

- Main's [UPDATE_MANAGER.md](UPDATE_MANAGER.md) and [TECH_STACK.md](TECH_STACK.md) remain byte-identical to the reviewed main. README, roadmap and compatibility references to update management, opted-in forks, distinct update channels and OTA/device safety are retained.
- Main's integration/regression-oriented policy remains authoritative: no TDD requirement, mandatory unit-test expansion, coverage target or frontend test stack. Existing risk-focused contract/path/platform regression tests are retained and run; integration does not delete existing safeguards merely because some use simulated inputs.
- Python 3.12+, uv, Typer/Rich, Pydantic v2, Ruff, Astral **ty**, pytest, and the approved future QEMU/C/LVGL/Svelte architecture are preserved. No dependencies or package-lock changes relative to PR #5.
- CLI validation, immutable source locks/cache behavior, doctor, trust/license inventory, firmware-free workflow and [handoff ADR](adr/0001-external-ui-handoff.md) are inherited unchanged. Runtime and proprietary firmware handling remain unimplemented.
- Source locks, schemas, provenance and license evidence remain byte-identical to PR #5. Cache identities remain the exact commit plus projection digest below. No automatic refresh, cache repair/migration or upstream execution is part of integration.

| Source | Commit | Projection digest in cache name |
| --- | --- | --- |
| diskOS | `4cd4a60003944b0cf4e8e5fb9feac2d07ea87df9` | `cb6c79cdb840efb2239becb82fb3fa5d` |
| Disco! | `485fe0ff685b3c386e679491cda74e275016b481` | `cb6c79cdb840efb2239becb82fb3fa5d` |
| QEMU source | `85ab00deb08ac112066377fd8083cc8727ed859a` | `ef1f0b45f86d4724a7359694b2c3bc4c` |

## Verification and acceptance

Run locked dependency installation, Ruff lint/format, `ty check`, pytest, actual CLI help/default doctor, valid and invalid manifest paths, source listing, offline source verification/sync from existing caches, license evidence hash comparison and documentation checks. A fresh local clone must use its own installed package/test environment, without depending on the original `.venv` or generated source files. Keep clone outputs ignored and firmware-free; use the existing validated cache only as an explicit read-only verification input.

Record the exact candidate SHA, clean-clone command results and complete candidate CI matrix in the integration PR. CI runs against GitHub's PR test-merge ref: retain its tested commit and tree identity, associated PR head SHA and base SHA, and distinguish it from earlier stack checks. Require an equivalent final tree and unchanged main before approval; if either changes, re-integrate and obtain fresh evidence. Hosted jobs are CLI/contract evidence, not WSL2/Docker/emulator acceptance.

No QEMU, firmware download/extraction/execution, real Docker daemon/containers, upstream builds or binaries, or hardware operations are permitted in this task. Those acceptance areas remain **NOT RUN**. No new runtime or M1 implementation belongs in this candidate.

## Readiness and recommended merge strategy

After candidate CI succeeds, **M0 can close following maintainer approval and integration of this reviewed tree**, provided main remains unchanged or is revalidated. It is not closed by preparing an unmerged Draft PR. Prefer merging this integration PR with a merge commit to preserve the main and stack ancestry once. After explicit approval, reconcile the original PRs as superseded/already integrated; do not separately squash/replay them onto the same tree. No original PR status or target is changed here.

The Lab root LICENSE/NOTICE remains unset, and the [initial license inventory](LICENSE-INVENTORY.md) still lists unresolved per-component attribution, asset/font, dependency and external QEMU patch/distribution rights. These block affected packaged/public releases and relevant component builds/distributions, rather than requiring a false claim of legal clearance to complete firmware-free M0. Owner decisions are necessary; this candidate chooses no license, modifies no upstream license, and redistributes no proprietary firmware.

The next technical task is **M1-01: pinned stock V2.57 QEMU runtime preparation**. Review exact runner/container/toolchain/shim/patch pins, lawful firmware identity/authenticity, dedicated isolation, privileges/mounts/network, cleanup and artifact policy. Resolve rights relevant to the planned operation before a build or distribution. Lawful local firmware intake and reproducible stock baseline acceptance follow later; custom UI execution remains gated by that baseline.
