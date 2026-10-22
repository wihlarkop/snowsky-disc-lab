# M2-06 synthetic UI acceptance evidence

Assessment: 2026-10-23, Asia/Jakarta. Implementation base:
`8434926bc885bb6fff0b9a52155c81adb31575ca` (PR #28 merged).
Delivery: [Draft PR #31](https://github.com/wihlarkop/snowsky-disc-lab/pull/31),
branch `codex/m2-synthetic-ui-acceptance`. The final exact-head CI links and SHA
are maintained in that PR description. No M2-02 or M5 files/dependencies changed.

## Executed hosted Linux observations

The initial implementation head `8913e2565b915da515ce081f6441d811a209d738`
completed real QEMU acceptance in [synthetic run 39824163885](https://github.com/wihlarkop/snowsky-disc-lab/actions/runs/39824163885),
job `119982899715`. [M0 run 39824164317](https://github.com/wihlarkop/snowsky-disc-lab/actions/runs/39824164317)
passed all four Ubuntu/Windows Python 3.12/3.14 jobs. The following identities
were measured in that QEMU run, not inferred from policy tests:

| Input/output | SHA-256 |
| --- | --- |
| First-party UI C source | `360f3d19f54c27a3a805a4be00a78a3d6531267306e88319b97dc0cb55b6e13f` |
| Compiled static MIPS32LE O32 guest ELF | `b52bd56817b67222ba396a22fc62ce91ae6c1522ec3f0fbe3f405ca718ad5f89` |
| Pinned QEMU executable | `2a58998c25a7836b910f255641a95e9d828967c75ed6b0de2e5490cb82038ddb` |
| Six-byte RIGHT input | `b4224f994c89262cdca3e998247bb72bba11cc62bd8560d01db7e16e554c8106` |
| Initial frame | `0d5adc52914d6a95b5befa9fa60900ba5ff56f20629d5bbdbf3c7bf6ef80be01` |
| Resulting frame | `540a51535f08e296a6dccc65b7825a61835d6380731668724af0b359ac179ef4` |

Frames are 16x8 RGBA8888, stride 64, 512 bytes each. The wrapper observed the
initial file's complete bytes before sending RIGHT. The guest processed that
input, moved its cursor from column 2 to 3, wrote the changed file and exited 0.
Both normal sessions produced the same frame hashes with distinct tokens
`416e47280f3f4481bbb9bb76f3ad9445` and `ad018328678c4fa1a14f9146a2ef7218`.

Wrong input exited 41, missing input 42, early exit 43 and stale exclusive-create
refusal 45. All six UI cases reaped the child, removed FIFO/frame files and
completed owned stopped-container removal, releasing private tmpfs. Host metadata
is intentionally retained. Existing filesystem, queue, handoff and supervision
acceptance also passed. Timeout/foreign ownership/partial cleanup policy tests
remain simulated Docker regressions; this report does not claim a broken daemon
was exercised. The existing supervision matrix exercises real owned child failure
and TERM/KILL behavior.

Inspection of this initial run found one report metadata inconsistency: the
inherited filesystem stdout limit said 1024 although the UI parser enforces 3072
ASCII bytes for full frame hex. The follow-up sets and validates the UI-specific
3072-byte receipt limit. It changes no guest/source/build identity or Docker
resource permission. Final-head CI is required after that correction; see PR #31.

The session pipeline rebuilt QEMU and the guest once. Its build receipt is
`firmware-free-build-passed-repeat-not-run`; this task does not claim a new
independent clean-build comparison. The separate build and legacy execution-smoke
workflows are branch-guard skipped. QEMU execution evidence is from the synthetic
session job above, not those skipped jobs.

## Local verification and Windows gap

132 focused UI/filesystem/queue/handoff/supervision/build regressions passed.
Ruff lint/format, locked Astral ty and diff checks passed. The Windows full suite
reported 658 passed, 3 skipped and one failure in the unchanged deterministic
firmware extraction test; that test passed alone. Hosted exact-head M0 is the
cross-platform regression result; the local full suite is not reported green.

[Windows/WSL2 diagnostics](M1-07-WINDOWS-WSL2-VALIDATION.md#bounded-recheck-on-2026-10-23-m2-06-session)
distinguish sandbox denial from a responding Linux Docker Engine. Its
8,242,479,104-byte total VM RAM cannot meet the existing 8 GiB available-memory
build gate. No local rebuild or guest run was forced. Local Windows runtime
acceptance is NOT RUN; dedicated trusted-VM isolation is unverified. M1-07 stays
open. Read-only diagnostics changed no ACL, WSL or daemon security configuration.

## Proof boundary and reproducible command

On a capacity-qualified Linux host, use the existing reviewed invocation:

```sh
python3 scripts/ci/qemu_runtime_build.py session
```

No external guest input is accepted. The same pinned toolchain, source manifest,
artifact rehashes, nonprivileged UID, no-network/no-IPC container, read-only mounts,
dropped capabilities, no-new-privileges, private bounded tmpfs, 256 MiB memory,
one CPU, 16 PID limit, and owned cleanup/quarantine apply. CI has contents:read,
no persisted checkout credentials or secrets, and exact same-repository branch
head checkout. The per-session guest deadline is 5 seconds with 1-second kill
grace; the existing outer deadline is 15 seconds.

Portable versioned receipts are synthetic and unauthenticated. They validate
internal consistency, not independent authenticity. This is a private regular-file
framebuffer with one logical input event. Real framebuffer drivers/ioctls, stock
binaries, touchscreen, LVGL assets, audio and hardware behavior are not covered.
No firmware/device/privileged-container execution or compatibility promotion
occurred. M1-04 remains NOT RUN / UNVERIFIED. M2-06's firmware-free fixture is the
only deliverable; the wider M2 and Windows runtime gates remain open.
