# Parallel Execution Playbook — SNOWSKY DISC Lab

**Applies to every Codex parent/subagent; follows [AGENTS.md](../../AGENTS.md).** This is an **operating procedure**, not permission to run vendor firmware, alter Windows/WSL resource limits, merge, release, or flash a DISC. GitHub [ROADMAP-001 #42](https://github.com/wihlarkop/snowsky-disc-lab/issues/42) is canonical for order, [OPS-001 #43](https://github.com/wihlarkop/snowsky-disc-lab/issues/43) for handoff and ChatGPT review, [QA-MANUAL-001 #44](https://github.com/wihlarkop/snowsky-disc-lab/issues/44) for unrun owner acceptance. Detailed functional gates remain in [docs/ROADMAP.md](../ROADMAP.md).

## 1. How new work enters GitHub Issues

**Create or reuse a GitHub issue before code or implementation subagents.** Do not treat a Markdown checklist or chat suggestion as a scheduled job. Put the complete *bounded* deliverable and acceptance in the issue; a master issue tracks the execution DAG, not another copy of product requirements.

Suggested issue template:

```markdown
# Mx-NN: clear outcome, not merely a broad investigation

Parent milestone: Mx
Status: PLANNED | PARTIAL | BLOCKED | READY (specific allowed scope)
Authorized scope: explicit owner request (link/date) or NOT AUTHORIZED
Dependencies (strict): issue #A, PR #B merged at SHA; optional research separate
Parallel eligibility: list independent peers, shared paths and constraints
Expected file ownership: specific paths/modules (mark contested paths SERIALIZED)
Goal / observable user-facing behavior:
- ...

Scope / implementation steps:
1. ...
2. ...

Acceptance evidence:
- Exact input/ref/binary/runtime IDs; commands actually run
- PASS / FAIL / NOT RUN / UNSUPPORTED / BLOCKED per scenario
- Expected output, failure/rollback and security/legal checks

No-go:
- Firmware trust, isolation, source redistribution, network secrets, physical access,
  cross-project code or permissions not authorized by the owner
Handoff:
- One focused Draft PR, exact remote base/HEAD, checks, outstanding owner QA
```

**On creation:** check duplicate issue and already merged code; link existing original issue/PR instead of opening duplicate. Use milestone codes `M1-01`, `M6-09` etc. Clearly separate *source-only review* from real executable test gates. Source-only work may be eligible without making the parent milestone's actual stock acceptance READY.

**On completion:** close an implementation issue only when its own true acceptance requirements are met. A foundation or synthetic PR can be merged as PARTIAL while the issue stays open. Record actual merge SHA and historical evidence in the issue, ROADMAP-001 and QA ledger. Never claim `verified-emulator` from host mock or `verified-device` from QEMU.

## 2. Authorization and dynamic issue DAG

- `next eligible issue`: choose one **owner-scoped** READY item from ROADMAP-001; one worktree/one active Draft PR; stop.
- `next eligible parallel wave`: one bounded set of independent READY issues, then STOP for ChatGPT review. If no active authorizations or all blocked, perform a read-only report only.
- `complete M1 with maximum safe parallelism`: dispatch independent M1 **firmware-free/source-only** implementation as allowed; when a strict predecessor has been independently reviewed and merged, reevaluate only direct dependents. **It does not waive** owner consent to inspect private ZIPs, extract, boot stock, use VM, modify WSL or reach hardware.
- `complete full Mx`: no M(x+1), no release, no unapproved optional feature. Owner-selected phase is a *scope*, not permission to waive safety/rights checks.
- A dependency edge `A → C` means C's **implementation** cannot begin until A's required **accepted source PR is merged** in the chosen integration base; a passing build, partial docs or Draft PR is insufficient. Other unrelated B may continue in parallel, and C need not wait for B unless it actually depends on B or owns the same file.
- When an issue has **multiple prerequisites**, every required merge and separate runtime/provenance approval must be present. A child may not redefine its parent issue's dependencies.

### M1 concrete issue DAG (source-only vs runtime)

```text
Initial independent source-only / firmware-free lanes:
    #45 M1-01 pinned runner/build reproducibility
    #46 M1-02 ZIP intake trust and identity review
    #51 M1-07 read-only Windows/WSL resource/isolation analysis
        (all may be worked in parallel ONLY when files/host resources are disjoint)

    #47 M1-03 source-only extraction-toolchain readiness may be reviewed
        separately; REAL extraction is BLOCKED on #46 + #45 and approved VM

Actual stock-runtime path:
    #45 ───────────┐
    #46 ───────────┼──> #47 ACTUAL extraction + stock hashes
    approved VM ───┘
    #45 + #46 + #47 + owner runtime authorization ──> #48 M1-04 stock boot
                                                           |
                                   +───────────────────────+─────────────────+
                                   v                                         v
                          #49 M1-05 stock media/audio                 #50 M1-06 lifecycle
                                   \                                         /
                                    +-------------------+-------------------+
                                                        |
    #45, #46, #47, #48, #49, #50, #51 supported-path acceptance --------> #52 M1-08
                                                                  final stock report
```

**Interpretation:** The source/research portions of #47 are not an excuse to start real extraction early. #49 and #50 may become **parallel** only after #48's actual stock boot acceptance is independently reviewed and merged; shared runner/guest outputs must remain serialized/isolated. #52 cannot close while M1-07 supported Windows path is unverified unless the owner explicitly changes the supported-host scope with a reviewed decision.

**Current evidence at issue creation:** #46 ancillary manifest refuses, #47 real extraction NOT RUN, #48 stock boot NOT RUN, #51 trusted local isolation unverified. Existing synthetics/hosted firmware-free Linux jobs remain bounded evidence, not a hidden green M1. Draft PR #41 researches exact-ZIP pin only; Draft PR #40 is separate M2–M10 vision.

## 3. Parent / child / optional grandchild responsibilities

- **Root coordinator (L0):** owner-authorized scope, global merged-prerequisite DAG, active PR/worktree inventory, resource and work reservations, stop rules, consolidated final handoff.
- **Issue writer (L1 or L2):** accountable for one issue/branch/PR, owns only reserved source paths and permitted verification; requests shared-contract integration instead of writing a sibling's files.
- **Component helper (L2/L3 if supported):** isolated read-only research, file-disjoint components or independent security review **inside parent issue authority**. No separate issue dispatch, privileges, merge or contract changes without coordinator approval.
- Verify actual harness support for parallel and nested spawning, per-agent model/effort selection, resource limits, cancellation and isolated worktrees. **If nested spawning unsupported, use root-managed flat children.** If independent branches cannot be isolated, serialize; never pretend multi-agent mode was active.
- **No artificial minimum or maximum agent count.** Root counts itself plus descendants and respects harness/host safe capacity, per-issue CPU/memory limits and overlapping source ownership. A 16 GiB Windows PC and resource-gated Docker VM are reasons to keep local parallel builds small; parallel source-only research on GitHub may still be safe.
- Parent/worker model/effort comes from the owner's actually supported configuration. Verify requested/acknowledged values; if identity is not observable, write `runtime identity UNVERIFIED`; do not claim source-deduced model identity or silently substitute a different provider.

## 4. Mandatory writer-reservation preflight

Before any tool writes/agent spawn, produce or update a table:

| Issue | Current state | Verified merged prerequisites | Owner/branch/worktree | Reserved paths | Resource/isolation gate | Expected output |
| --- | --- | --- | --- | --- | --- | --- |
| #45 | READY only in authorized firmware-free scope | M0 reviewed | A / isolated W1 | `scripts/ci/qemu_runtime_build.py`, pinned runner receipts | CPU/RAM CI | repeatable build receipt |
| #46 | READY only for source/evidence-only scope | M0 / PR #39 merged | B / isolated W2 | `firmware_intake.py`, associated tests/schemas only if reserved | no real ZIP access | exact-package identity evidence, no admission change |
| #51 | READY only for read-only Windows diagnostics scope | M0 | C / isolated W3 | `windows_readiness.py`, dedicated docs if reserved | **no** WSL configuration/VM execution | honest resource/isolation diagnosis |
| #47 | PARTIAL/read-only research | none for docs; real extraction #45+#46 | separate W4 if capacity | extraction-specific toolchain research only | rights/VM/owner authorization | extraction gate design, NOT actual plaintext |

These are **illustrative reservations, not a standing owner execution order**. Inspect existing PRs first, then assign actual workers and paths. If #45 and #47 both need a shared extractor/runner contract or #46 and #47 both need `docs/FIRMWARE-INTAKE.md`, reserve one integrator; defer the conflicting edit rather than concurrent merges.

**Shared single-writer paths:** `AGENTS.md`, `docs/ROADMAP.md`, ROADMAP-001/OPS-001 and ADRs, `upstreams.lock.yaml`, `uv.lock`, `pyproject.toml`, `firmware_intake.py` and its receipt schemas, public CLI interfaces, QEMU runner/shim/build scripts, runtime guest/IPC contracts, common provenance and signed-update policies. A separate worktree is necessary but *not sufficient* to claim independent write safety.

## 5. Draft PR + independent ChatGPT review contract

Every issue-level Draft PR must identify:
- `Refs #issue` or `Closes #issue` **only when completion is genuinely demonstrated**. Use `Refs` for partial/non-executable foundation.
- Exact original remote base SHA and current HEAD SHA, issue/accountable writer/branch, verified merged prerequisite SHAs, permitted and prohibited work.
- Source files and compatibility impact, exact reproducible commands, CI URLs and **PASS/FAIL/NOT RUN** (never claim checks that were not run).
- Proprietary firmware boundary, vendor authenticity vs exact source byte identity, licensed third-party dependencies, VM isolation, absence/presence of actual runtime execution.
- Observed versus expected UI/audio/frame/IPC behavior; distinguish synthetic mock, hosted Linux, Windows/WSL and physical device.
- A short Windows PowerShell-first owner acceptance checklist, expressly marked PENDING/DEFERRED if not performed.
- All remaining blockers, unresolved owner decisions, independent security review findings and required same-PR repairs.

**Codex stops at Draft PR.** ChatGPT checks the **exact remote HEAD** rather than a stale review, verifies actual base/mergeability, then may merge only after scoped owner authorization and no actionable P0/P1/integration/trust blockers. After merge it updates #42/#43/#44, closes only genuinely satisfied issues, and leaves newly eligible downstream implementation for a separately owner-invoked run. No background agents or auto-polling.

## 6. Safety checklist — cannot be delegated away

1. No vendor FiiO ZIP/rootfs/chunks/stock binaries or personal SD music in code, CI, PR attachments, chat logs or public artifacts.
2. No unsafe self-referential SHA convention invention or skipped manifest checks disguised as authenticity; whole ZIP hash equality does not prove publisher signature.
3. No source download/extraction/firmware execution via shared-kernel privileged container; verify dedicated disposable VM, bounded resources, no secrets/network/devices/mount escape and explicit owner permission **separately**.
4. QEMU user-mode is **not** X2000 hardware certification; no hardware installation or firmware write without M9-style authorization/verified recovery steps.
5. No zero-repro CI green claims when actual stock UI/player, touch, full PCM and lifecycle are NOT RUN; no arbitrary tests/CI ban borrowed from other project docs.
6. No dirty worktree deletion, force overwrite, altered Windows .wslconfig/ACL, unsupported subprocess escalation, unreviewed trust-policy change, or upstream source-lock promotion to obtain an easier PASS.

**Operating invariant:** maximum independent verified work **within strict issue DAG and authorization**, not maximum unreviewed code, agent count or apparent PASS statuses.
