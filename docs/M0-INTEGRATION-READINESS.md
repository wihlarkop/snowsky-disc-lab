# M0 integration readiness

The original M0-08 review below was recorded against PR #4 at `f91d20ee3f3c92266445637bf54c72c44635b03d`. The later [final integration candidate](M0-FINAL-INTEGRATION.md) combines PR #5 with newer main decisions and supersedes the original stack/CI recommendations for that candidate. Historical verification below retains its original scope; it is not runtime acceptance.

## Stack and integration order

| Order | Draft PR | Reviewed head | Base |
| --- | --- | --- | --- |
| 1 | [#2 — foundation](https://github.com/wihlarkop/snowsky-disc-lab/pull/2) | `67982764c2fa0585ef4d6a1c68616cba9e9da52a` | `main` |
| 2 | [#3 — source cache](https://github.com/wihlarkop/snowsky-disc-lab/pull/3) | `9025c2e4c6ca46a075ccfed7e95aa7e2bfdd914a` | `codex/issue-1-m0-foundation` |
| 3 | [#4 — preflight and trust](https://github.com/wihlarkop/snowsky-disc-lab/pull/4) | `f91d20ee3f3c92266445637bf54c72c44635b03d` | `codex/m0-source-cache` |
| 4 | M0-08 documentation successor | See this PR's head | `codex/m0-preflight-trust` |

All three preceding PRs were open at review time. Review in this order; after each integration, retarget the next PR and inspect its merge-base/diff, especially if squash/rebase changes ancestry. Preserve the source pins and existing cache identities. Obtain green firmware-free CI on the final integrated head before closing M0. These are recommendations; no PR was merged or retargeted in this task.

## Accumulated implementation review

The package uses one Python 3.12+ CLI, Pydantic v2 contracts and bounded YAML loader. Source resolution is separate from UI/firmware manifest interpretation. Doctor reuses source-cache path resolution and reports metadata; it does not claim to verify cache integrity. Use `sources verify` for that. No second configuration system, dependency change or cache migration is needed for the ADR.

The current `lab-ui/v1` schema remains authoritative. Its source revision, build preset and runtime declarations are data, not approved executable recipes. Future manifest-free binary inspection is a separate input path, not an exemption from required fields when a manifest is supplied. Schema success cannot authorize M2 execution.

This review aligns the proposed adapter vocabulary to `inspect`, `build`, `preflight`, `launch`, `stop`, `collect`, `report`; preparation is a confined internal phase of `launch`, after preflight approval. It also replaces architecture examples that used unsupported manifest fields and the stale recommendation to start M0-01/M0-03. The [handoff ADR](adr/0001-external-ui-handoff.md) governs future lifecycle design. No adapter implementation or Python API stability is implied.

## Verification evidence

On Windows x86-64 / Python 3.14.0, against the unchanged implementation inherited from PR #4:

| Check | Result |
| --- | --- |
| `uv run ruff check .` | PASS |
| `uv run ruff format --check .` | PASS; 29 Python files |
| `uv run ty check` | PASS |
| `uv run pytest` | PASS; 142 passed, 1 skipped (POSIX FIFO on Windows) |
| `uv run disc-lab sources verify` | PASS; all three existing projections, offline, no repair/replacement |
| Documentation checks | PASS; 67 local Markdown targets exist, architecture YAML validates against current `UIManifest`, `git diff --check` clean |

Git fixture tests used process permission outside the Windows helper-process sandbox. No upstream tests or scripts were invoked. Prior clean-clone/default doctor and license-hash evidence remains scoped to [PR #4's verification record](M0-PREFLIGHT-VERIFICATION.md); it was not repeated as a new clean-clone run here.

A one-time GitHub snapshot confirmed [run 39294363186](https://github.com/wihlarkop/snowsky-disc-lab/actions/runs/39294363186) succeeded at **exactly `f91d20ee3f3c92266445637bf54c72c44635b03d`**: Ubuntu and Windows, Python 3.12 and 3.14, all four jobs green. This supersedes the older report's then-pending PR #4 CI observation. It does not establish CI for this successor or a future merged head. New CI is **NOT AWAITED**, per user instruction.

The historical preview and current runtime were inspected as source/text only. Firmware intake/extraction, QEMU, upstream binaries/builds, Docker daemon contact, containers, real WSL2 runtime, virtualization, write/ACL probes, and physical-device acceptance: **NOT RUN**. Mocked platform tests and hosted Linux CLI tests do not establish WSL2/Docker runtime compatibility.

## Gates and unresolved risks

| Gate | Blocks | Remaining action |
| --- | --- | --- |
| Stacked review/integration and exact integrated-head CI | Formal M0 closure | Integrate in dependency order and record the final SHA/results; this Draft PR supplies M0-08's design deliverable only. |
| Root Lab LICENSE/NOTICE unset | Packaged/public release of Lab code | Explicit owner decision; this PR selects no license. |
| Component-specific `NOASSERTION`, attribution, fonts/assets, optional dependencies, external QEMU patch/distribution rights | Builds/distributions relying on unresolved components | Complete the relevant per-file review from [the initial inventory](LICENSE-INVENTORY.md). Repository MIT metadata does not clear GPL UI or external QEMU. |
| Firmware provenance/authenticity, exact runner/toolchain/image/patch pins and safe local state | M1 executable use | Review M1 preparation before intake/runtime; never bundle or publish vendor firmware. |
| Host VM/global binfmt and loop-device effects | M1 runtime isolation, later concurrent sessions | Use a dedicated runtime boundary; do not reconfigure a shared VM registration under unrelated sessions. Validate isolation experimentally. |
| No Lab stock V2.57 evidence | M2 custom UI execution | Establish stock boot/input/IPC/PCM/stop/restart baseline before any custom adapter. |
| Historical warm handoff only, with known playback limitations | Warm UI replacement | Deferred; requires exact-combination review and full lifecycle/playback evidence, not a V2.40 screenshot. |

No reproducible cross-PR implementation regression was established by this bounded review and existing tests; this is not an exhaustive security audit. M0's initial license inventory and firmware-free host target are deliverables, not complete redistribution clearance or emulator host acceptance. Missing runtime evidence is expected for M1/M2, rather than a reason to falsely mark M0 diagnostics as runtime support.

## Recommendation

M0's scoped implementation and design deliverables are ready for maintainer review, including M0-08. **Do not close M0 yet:** the stack is still unmerged and exact integrated-head CI is outstanding. License decisions remain release gates, with any rights relevant to an M1 build resolved before that build. No firmware/UI pair is promoted from `unknown`/NOT RUN.

The first M1 task is **stock V2.57 QEMU runtime preparation**: inventory and pin the runner, container/toolchain and patches; specify lawful local firmware identity/authenticity checks, isolated state, privilege/network/mount policy, ownership/cleanup and artifact allowlist. Do this before implementing intake or running firmware. Then establish the reproducible stock baseline; reviewed external UI adapters follow in M2 under the ADR.
