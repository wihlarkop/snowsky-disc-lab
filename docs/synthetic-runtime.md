# Firmware-free synthetic runtime sessions

The fixed first-party session exercises launcher ownership, filesystem syscalls
and container isolation through the reviewed QEMU interpreter. It does **not**
mount a firmware rootfs, boot an OS or establish stock V2.57 compatibility.
M1-04 stock boot remains **NOT RUN / unverified**.

From the repository root on a sufficiently sized Linux Docker host:

```console
python3 scripts/ci/qemu_runtime_build.py session
```

This developer invocation reuses the existing capacity gate, reviewed source
fetch, signed Debian snapshot audit, digest-pinned image, toolchain, QEMU and shim
build, and MIPS execution smoke. It builds once and runs the fixed session
journey. It accepts no command, binary, rootfs, firmware or arbitrary build input.
There is no public preparation operation. The PR workflow checks out the exact
PR head with read-only repository permissions and no persisted credentials or
secrets. It also supports input-free manual dispatch only from the canonical
repository's `main` branch and checks out that exact dispatch SHA.

## Upstream evidence and synthetic mappings

The reviewed upstream is `eudj1n/snowsky-disc-qemu` at
`85ab00deb08ac112066377fd8083cc8727ed859a` (unchanged source projection
`ef1f0b45f86d4724a7359694b2c3bc4c`). Its
[`run.sh`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/run.sh),
[`compose.yaml`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/compose.yaml),
[`lib.sh`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/scripts/lib.sh),
and [runtime limits](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/docs/limits.md)
are source evidence, not Lab stock acceptance.

Upstream Compose declares a privileged emulator, `/ota:ro`, writable `/repo`,
`/sdcard`, and persistent `/work`. Its helpers select QEMU, chroot into
`/work/rootfs`, and describe binfmt, namespace and SD mount setup. Those operations
are not reused here. Only the existing separately reviewed build is reused.

| Upstream role | Synthetic binding | Enforced behavior |
| --- | --- | --- |
| Extracted `/work/rootfs` inputs | `/synthetic-rootfs` | Small first-party marker tree; read-only bind, rehashed before start |
| `/usr/data` writable userdata | `/session-data` | One private 1 MiB tmpfs; ephemeral |
| Temporary files, including future card paths | `/session-tmp` | One private 1 MiB tmpfs; no card or block-device model |
| `/work/shots` and runtime diagnostics | `/session-diagnostics` | One private 1 MiB tmpfs; bounded stdout/stderr; only validated observations exported |
| Pinned interpreter and fixed first-party guests | `/inputs` | Exact measured QEMU and guest ELF files, regular, non-hard-linked, executable and read-only; the queue guest is used only by `session` acceptance |
| Guest `/dev`, `/proc`, `/sys` | Marker files under the synthetic input tree only | No emulated device/kernel interfaces; no extra proc, mqueue or sys mounts |

The synthetic `/usr/data` and `/tmp` marker directories are descriptive inputs;
the writable areas use the explicit bindings above. Nothing is named or presented
as a genuine stock `mq_ui`, `mq_player` or firmware library.

## Enforced boundary

Before starting a container, the launcher validates its ID and unpredictable
ownership label, exact image and command, UID/GID, default environment, complete
bind-source allowlist, mount modes, tmpfs settings, and Docker HostConfig. It
requires `--network none`, `--ipc none`, a read-only container root, UID/GID
65534, all capabilities dropped, no-new-privileges, 256 MiB memory and swap,
one CPU and 16 PIDs. No ports, device requests, extra capabilities, shared PID/IPC/
UTS namespace, volumes-from, host home, source cache or Docker socket are allowed.
Writable tmpfs mounts are `nosuid,nodev,noexec`, owned by UID/GID 65534, mode 0700.

The normal and expected-failure guests have five-second deadlines. The deliberate
busy loop has a two-second deadline with a one-second TERM-to-KILL grace period.
The host bounds each attached execution to 15 seconds and each Docker control
command to 30 seconds. Diagnostic files have a 64 KiB file-size limit within the
1 MiB tmpfs; exported guest stdout is at most 1 KiB. Core dumps are disabled.
Unexpected stdout, stderr, exit status, OOM or running state fails the session.

The fixed MIPS32LE O32 guest actually calls `open`, `read`, `write`, `lseek` and
`close` via QEMU. Successful observations require:

1. The expected synthetic input marker is read byte-for-byte.
2. Opening it for truncation fails with Linux `EROFS` (30).
3. Private data and temporary files are exclusively created, written and read back.
4. Creating a file outside the writable bindings fails with `EROFS` (30).
5. An unmounted host-path probe returns `ENOENT` (2).
6. Exact bounded output and exit 0 are observed; Docker confirms termination.

These are specific syscall outcomes. They do not establish a general read-access
jail: container-image files and Docker-managed kernel interfaces may be readable.
QEMU user mode uses the container/host kernel; this is not a full guest kernel or
an independently constructed guest mount namespace. No host chroot, mount changes,
binfmt registration, SYS_ADMIN or physical passthrough is performed.

## POSIX message queue acceptance

The `session` command also compiles and runs a separate fixed MIPS32LE O32 queue
guest through the same pinned QEMU build. It uses only the synthetic name
`/snowsky_disc_lab_mqueue_probe_v1`, `O_CREAT | O_EXCL | O_NONBLOCK | O_RDWR`,
mode 0600, two messages and 64-byte messages. It sets no queue limit or sysctl.
The container stays on `--ipc none`, with UID/GID 65534, no capabilities,
no-new-privileges, read-only inputs and root, the existing private tmpfs, and the
existing CPU, memory, process and time limits. No `/dev/mqueue` mount is added.

QEMU syscall tracing must show `mq_open`, `mq_getsetattr`, `mq_timedsend`,
`mq_timedreceive`, `mq_unlink` and `close` for the first session, plus the calls
used by the second session. The guest verifies queue attributes and mode, the
duplicate `EEXIST`, exact payload bytes and priority, close/unlink, and `ENOENT`
after unlink. It then recreates the queue and exits while it remains linked. The
owned container is terminated and removed before a second fresh container
attempts an exclusive create of the same name. The second guest removes its queue
and verifies `ENOENT` after unlink. Trace text stays in the bounded private
diagnostic tmpfs; the receipt includes only the fixed observed syscall names,
numeric errors, verified payload digest, guest-output digests, durations, session
identities, inspected security profile and cleanup outcomes.

The CI summary adds a versioned `posix_mqueue` receipt to the existing synthetic
runtime receipt. If a syscall fails under QEMU, seccomp, the kernel or current
queue limits, acceptance fails with only a bounded stage and numeric errno.
Documented stock queue attributes remain unverified; this probe makes no claim
about stock queue names, sizes, shims, protocol or IPC compatibility. M1-04 stock
boot remains **NOT RUN / unverified**.

An initial hosted probe observed raw `mq_flags=2048`, which did not match the
guest's numeric `O_NONBLOCK` constant even though maxmsg 2, msgsize 64 and
curmsgs 0 matched. The fixed guest now verifies nonblocking behavior directly:
an empty receive must return `EAGAIN`, avoiding a host-versus-target numeric flag
assumption.

## Two-process POSIX queue handoff

The `session` acceptance additionally runs one fixed consumer and one fixed
producer as separate MIPS32LE O32 QEMU processes at the same time inside each
owned container. The consumer exclusively creates the request and acknowledgment
queues, validates their mode and attributes, receives the fixed request, verifies
its exact bytes and priority, sends the matching acknowledgment, then closes and
unlinks both queues. The producer waits for queue readiness with bounded
nonblocking opens, sends the fixed request, validates the acknowledgment bytes
and priority, and closes both descriptors. Each queue uses mode 0600, two
messages and 64-byte message bounds. No stock queue name or message format is
used.

This protocol uses two independent, five-second bounded guest roles and preserves
the existing 15-second outer execution deadline. A fixed shell wrapper starts
both QEMU processes before waiting for either, captures each role's bounded
output and status separately, and exports only fixed result fields and an
allowlisted syscall-name trace. The request/acknowledgment round trip proves
that both processes overlapped in the same inspected container and therefore
shared its private IPC namespace. The same protocol is then repeated in a fresh
container to check session separation. Container ownership, inspection, removal,
and all existing mount and resource controls remain governed by the existing
runtime session.

The additional `synthetic_ipc_handoff` receipt uses schema
`firmware-free-mips32le-synthetic-ipc-handoff/v1`. It records pinned QEMU and
guest source/ELF identities, fixed queue and payload attributes, the two role
statuses, verified payload digests and priorities, syscall names, bounded
output digests and durations, session identities, isolation inspection, and
cleanup. Failure output is reduced to a fixed role, stage, and errno; raw
diagnostics remain inside the private container. This is first-party IPC
acceptance under unchanged `--ipc none`, without `/dev/mqueue`, limit changes or
sysctl changes. Stock IPC compatibility remains **UNVERIFIED**, and M1-04 stock
boot remains **NOT RUN**.

The complete hosted acceptance passed on implementation head
`cd6d40a2ae242976ba8f1872b127ed7da14cf250` ([synthetic runtime run](https://github.com/wihlarkop/snowsky-disc-lab/actions/runs/39656237048)); exact-head M0 also passed all four jobs ([M0 run](https://github.com/wihlarkop/snowsky-disc-lab/actions/runs/39656237120)). The sanitized v1 receipt records QEMU SHA-256 `2a58998c25a7836b910f255641a95e9d828967c75ed6b0de2e5490cb82038ddb`, queue-source SHA-256 `459656e8b14e24c2ab1f2ab97d2219c978b290203168d20e6c8a8554c0ae6795`, and guest-ELF SHA-256 `fc0c25cc07b072851f9ed20e1e1af6d084193a05a07776d4e6d15ecad2a824e5`.

Under unchanged `--ipc none` and without a `/dev/mqueue` mount, the first session verified mode 0600, maxmsg 2, msgsize 64, empty count, empty-receive `EAGAIN`, duplicate `EEXIST`, exact 28-byte payload and priority 7, close/unlink, and `ENOENT` after unlink. It recreated the queue and left it linked until its container was removed. A second, distinct container identity then exclusively created the same queue name and verified its attributes, `EAGAIN`, close/unlink and `ENOENT`. Both containers and private tmpfs instances were removed; the receipt records output digests and durations. Existing filesystem, expected-failure and timeout acceptance also passed. No stock queue behavior is inferred, documented stock attributes remain unverified, and M1-04 stock boot remains **NOT RUN**. Raw guest output is never retained.

## Bounded two-process supervision and recovery

The `session` acceptance compiles one versioned companion guest beside the
existing, unchanged filesystem, queue and successful handoff guests. Its fixed
matrix runs once in each of two separately created containers:

1. The existing consumer/producer request and acknowledgment completes normally.
2. The consumer exits with status 42 before a request; the waiting producer is
   signaled and reaped.
3. The producer exits with status 43 after seeing the consumer's unread
   acknowledgment queued. It exits without consuming the acknowledgment; the
   consumer's send path completes, then the waiting child is signaled and
   reaped.
4. The producer enters a fixed busy loop; the two-second watchdog sends TERM to
   both children and reaps them, with a one-second KILL fallback for a child
   that does not exit during grace.
5. The producer exits with status 44 before creating a queue; the already
   observed waiting consumer is signaled and reaped.

The wrapper starts only the measured fixed QEMU executable with one of the two
first-party guest ELFs and fixed role/scenario arguments. Each QEMU PID is tracked
and waited independently. Signal delivery targets only those recorded child
PIDs; timer and grace PIDs are also tracked and reaped. Per-role exit status,
exit reason, PID, bounded output digest, TERM/KILL outcome and reaping are
validated separately. Raw stdout and syscall diagnostics stay in the private
diagnostic tmpfs; the receipt keeps fixed fields and hashes. A shell-wrapper
failure is recorded separately from a guest observation mismatch and from
container ownership or cleanup failure.

The companion guest uses fixed, scenario-specific POSIX queue names and
`O_CREAT | O_EXCL`. The first container is stopped and removed after the matrix.
The second container then repeats the same names. Successful exclusive creates
in the second matrix, distinct session identities and reaped children establish
that no queue name or process survives the first container. The existing
successful handoff still closes and unlinks its queues. Container inspection
verifies the owner label before removal and confirms stopped state; removal
releases the private tmpfs instances.

The receipt schema is
`firmware-free-mips32le-synthetic-ipc-supervision/v1`. It records both guest
source/ELF identities, pinned QEMU identity, roles and process identities, all
five outcomes, deadline and signal behavior, queue recreation, observed
container ownership and isolation, cleanup, and actual-versus-simulated evidence.
The two-process cases run through actual QEMU processes on the shared
container/host kernel. Docker isolation and cleanup policy unit tests remain
simulated; hosted acceptance records the real owned-container lifecycle.
`--ipc none`, `--network none`, UID/GID 65534, dropped capabilities,
no-new-privileges, read-only root and inputs, private fixed tmpfs, and existing
CPU, memory, PID and outer-deadline limits remain unchanged. No new mounts,
sysctls, host PID operations or global process-name signals are used.

The fixture is synthetic. Compatibility with stock firmware, binaries, queues,
or device behavior remains **UNVERIFIED**. M1-04 stock boot remains **NOT RUN**.

## Lifecycle, retention and receipts

Each session reserves a fresh directory without replacement and a fresh labelled
container. Input and store paths reject links/junctions, traversal and mount-option
injection; exact artifact hashes and synthetic file contents are checked again
before start. Linux stores must be current-user-owned and private. Windows ACLs
and WSL2/Docker runtime behavior are not accepted by this Linux experiment.
A trusted, quiescent filesystem owner and Docker daemon are assumed; same-user
path races and a hostile daemon are outside this boundary.
Retention is capped at eight acceptance directories, each with at most 32 sessions;
the global cap is checked before source downloads or builds. At capacity the
invocation refuses and asks for operator review; it never deletes older sessions.

The acceptance journey runs two separate successful filesystem sessions, the expected exit-23
failure and the deliberate timeout (124). Both successful sessions must exclusively
create the same private filename, demonstrating fresh independent tmpfs state.
It also exercises existing-ID, traversal and symlink-ancestor refusals. Hosted
firmware-free regressions cover unexpected mount sources/security drift, outer
timeout and cleanup failure; those regressions simulate Docker rather than claim
that a broken daemon was exercised in real acceptance.

Only the exact created container ID with the session's matching ownership label
can be force-removed, after normal completion or failure. Uncertain ownership or
failed removal quarantines the session and fails acceptance. An ambiguous create
may leave a labelled container requiring operator inspection; it is never removed
by global name/PID matching. No other containers or session directories are cleaned.

Guest writable state disappears with its container; persistent stock userdata is
unimplemented. Small synthetic input files, an owner marker and a sanitized receipt
remain under ignored `.lab/synthetic-runtime-sessions/<acceptance-id>/<session-id>`.
Failed state stays quarantined there. There is no recursive session cleanup.
Compiled QEMU/guest files remain in the existing build helper's private temporary
directory and are removed through its established lifecycle, never published.

The CI summary's existing `QEMU_RUNTIME_RECEIPT_JSON` gains a `synthetic_runtime`
member with version `firmware-free-synthetic-runtime-acceptance/v1`. Existing
receipt schemas and policy identifiers retain their meanings. The member records
QEMU artifact/source/toolchain identities, first-party source/ELF hashes, measured
synthetic input identity, inspected sanitized mounts, resource settings, each
session's lifecycle, exit/output digest/duration, observed syscall results,
timeout/termination/cleanup and unsupported capabilities. Per-session local
receipts use `firmware-free-synthetic-runtime/v1`. No raw daemon errors, host paths,
unreviewed guest diagnostics, binaries, images or firmware are exported.

The [V2.57 capability map](v257-runtime-capability-map.md) separates these verified
observations from upstream path, syscall and privilege requirements. Its
[test-only boundary contract](v257-runtime-boundary-contract.json) checks existing
container refusals; it adds no runtime inputs or execution authority. The
two-process supervision acceptance is synthetic and does not authorize firmware
execution. Lawful firmware identity/authenticity, rights review and explicit
firmware-backed runtime authorization remain separate gates.


## M2-06 synthetic UI acceptance

The same `python3 scripts/ci/qemu_runtime_build.py session` path now also builds
one reviewed first-party static MIPS32LE O32 UI guest with the existing pinned
compiler. It executes six fresh owned containers: a normal input/frame journey
twice, wrong input (exit 41), missing input (42), early exit (43), and an existing
frame exclusive-create refusal (45). No external executable or source is accepted.

The guest draws a 16 by 8, stride-64 RGBA8888 frame into a private regular file.
A solid cursor starts in column 2. A fresh token-bearing guest handshake follows
the completed frame write. The wrapper reads the complete frame bytes before
sending the six-byte `RIGHT\n` event through a private FIFO. The guest reads that
event and draws a second frame with the cursor at column 3. The wrapper reads the
second frame only after the guest exits and emits its matching-token completion.
The Python host compares both complete observed byte arrays with an independent
pixel oracle, then hashes the observed bytes. A log line or declared digest alone
cannot satisfy this acceptance. No fixed sleep is used for readiness.

All paths, modes, payloads, geometry and commands are fixed. The existing
network/IPC isolation, unprivileged UID, tmpfs, CPU/memory/PID limits, TERM/KILL and
outer deadlines, exact artifact rehashes, container ownership and quarantine
remain in force. Wrapper waits reap its owned child; FIFO/frame unlinking is
checked before exit. Container removal releases all writable tmpfs including
private diagnostics. Small host metadata remains intentionally retained.
Foreign session reuse, deadline, failed child and partial cleanup refusals reuse
the existing runtime controls; policy regressions simulate Docker. The six UI
scenarios in the session workflow execute real QEMU.

`firmware-free-mips32le-synthetic-ui/v1` binds source, measured ELF, pinned QEMU,
fixed input, per-session token, frame geometry/digests, event/guest exit, inspected
isolation and cleanup. Deterministic fields are separate from random session
tokens. `synthetic_ui.parse_receipt` bounds JSON and rejects duplicate keys;
`validate_receipt` rejects incomplete/contradictory observations and cleanup.
Portable receipts are explicitly unauthenticated. Authenticity requires checking
the actual run provenance and measured artifacts independently.

This models a private regular-file framebuffer and one logical key, without
LVGL, fonts, vendor assets, stock drivers/ioctls, touchscreen or hardware claims.
It completes only the firmware-free M2-06 fixture, subject to exact-head hosted
acceptance. M2 as a whole remains open; M1-04 is NOT RUN / UNVERIFIED. It grants
no `verified-emulator` or `verified-device` firmware compatibility status.
