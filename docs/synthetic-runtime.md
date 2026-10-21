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
container refusals; it adds no runtime inputs or execution authority. The proposed
smallest follow-up is a bounded two-process first-party queue handoff under the
same unchanged isolation profile. Lawful firmware identity/authenticity, rights
review and explicit firmware-backed runtime authorization remain separate gates.
