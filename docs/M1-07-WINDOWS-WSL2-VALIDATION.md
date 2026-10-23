# M1-01 Runtime Reproducibility and M1-07 Windows/WSL2 Validation

**Assessment date:** 2026-10-22
**Repository baseline:** `3625df30805f570c148fccc6bf6d928de7d6795e`
**Status:** M1-01 and M1-07 remain open. M1-04 stock firmware execution remains **NOT RUN / UNVERIFIED**.

## Runtime build verification changes

The existing pinned QEMU build pipeline remains the source of build evidence. The build receipt is now rejected unless it contains complete, internally consistent identities for the five static ELF artifacts, signed Debian snapshot metadata, archive keyring, canonical installed-package BOM, fakeroot bootstrap package hashes, native and MIPS toolchain versions and executable hashes, MIPS sysroot tree, reviewed input manifest, configure flags, build logs, container limits and output retention. The host compares the returned manifest digest with the digest it prepared before accepting the receipt.

Independent clean builds now compare those identities and full artifact records. Missing or unknown evidence is an error; an incomplete comparison cannot be called `identical`. Repeat statuses are explicit. A differing or attempted-but-failed repeat makes the build command fail. A resource- or time-gated repeat remains `not-run`, with its reason recorded; it is not reported as reproducible.

The existing firmware-free acceptance remains the implementation under test. The pull request CI runs the QEMU build/repeat workflow and the existing synthetic runtime session workflow.

## Windows host diagnostics

Read-only diagnostics were attempted from this Windows CLI. The CLI did not expose enough host state to validate a Windows build or the required isolation boundary.

| Capability | Observation | Result |
| --- | --- | --- |
| Windows version/build and host virtualization details | CIM queries for `Win32_OperatingSystem`, `Win32_ComputerSystem` and `Win32_Processor` returned “Access to a CIM resource was not available to the client.” | Unknown from this CLI |
| WSL installation and distributions | `wsl.exe` exists at `C:\Windows\system32\wsl.exe`; `wsl.exe --status` and `wsl.exe --list --verbose` returned `Wsl/E_ACCESSDENIED`. | No distribution or WSL2 state verified |
| Docker Engine | Docker CLI 29.7.2 is installed. `docker version` could not connect to `npipe:////./pipe/dockerDesktopLinuxEngine`. | Engine unavailable to this CLI |
| Docker Compose | Compose CLI 5.4.0 responds. | CLI only; no working Engine |
| Python build helpers | `uv` 0.13.0 and Python 3.12.13 are available. | Helpers available; pinned Linux container build prerequisites are not |
| Dedicated VM and isolation boundary | No accessible host/daemon evidence demonstrates a dedicated VM or the required filesystem, resource and process isolation. | Not established |

No Docker build, QEMU invocation, synthetic filesystem acceptance, message queue, IPC handoff, supervision or termination test was run on Windows. No access-control bypass, privileged container, device passthrough or global `binfmt` mutation was attempted. Docker Desktop or WSL2 presence alone would not establish the dedicated VM boundary.

## Hosted Linux evidence

The following PR-triggered workflow runs used code head `d5d053e02d7b2e0be9fd8b90a07a41214c039387` on branch `codex/m1-runtime-repro-wsl2`, based on `3625df30805f570c148fccc6bf6d928de7d6795e`. They are Linux hosted-runner results; this report-only follow-up does not change the tested implementation.

### QEMU runtime build and repeat

- Firmware-free QEMU runtime build run [#16](https://github.com/wihlarkop/snowsky-disc-lab/actions/runs/39797079902), job `qemu-runtime-build` (`119886965746`): **completed / success**.
- Primary build status: `passed` (77.4 seconds). A resource-checked clean repeat completed in 76.9 seconds; overall receipt elapsed time was 169.6 seconds.
- Repeat status: `identical`; the recorded comparison list was complete and had no differences. Host capacity checks were sufficient before both builds. Temporary build container cleanup was verified.
- Both builds recorded these artifact SHA-256 values:

  | Artifact | SHA-256 |
  | --- | --- |
  | `qemu-mipsel` | `2a58998c25a7836b910f255641a95e9d828967c75ed6b0de2e5490cb82038ddb` |
  | `fbshim.so` | `9bb964e2e216ba105d3990c212f34e8d4e4b26e7f773e16e0e930e256d6d7abc` |
  | `asndshim.so` | `c08f2c1e86cdf8a7ffebe50daedd47da6a6a2c9506ffc3f2114e17c39303a346` |
  | `tinyshim.so` | `c9e81647d23b2025f4400f6997cf67350dae59ebcbef165bcca96bb3951aba16` |
  | `mqshim.so` | `f3523ef246171ec60a02f70399bc3b735df48937bbb86f1f5996aa53b041048b` |

- Package BOM SHA-256: `161eceffac7fdadb5b5999ad9a7ce86bde097ced47413366b94bcb326c888481` for both builds. MIPS sysroot SHA-256: `96cd2b889c0fb0b4e8507944aa3bce80a0d5088e1606e1a8a5d6d8198954047f` for both. Prepared input manifest SHA-256: `3d1ade1b5ec41b37f8ef5b261390f1d115dd199946bd8b7b7109e53ea7e68646`. Pinned QEMU source commit: `85ab00deb08ac112066377fd8083cc8727ed859a`; reviewed projection digest: `ef1f0b45f86d4724a7359694b2c3bc4c`.
- This workflow built but did not invoke QEMU, boot a guest, process firmware, or publish artifacts. Its receipt records redistribution clearance as pending review; compiled outputs and container images were not published.

### Synthetic runtime acceptance

- Firmware-free synthetic runtime run [#17](https://github.com/wihlarkop/snowsky-disc-lab/actions/runs/39797079941), job `synthetic-runtime` (`119886964934`): **completed / success** on the same code head.
- Synthetic runtime status: `passed`. Filesystem sessions, POSIX message queue sessions, IPC handoff, and IPC supervision passed; session containers and private temporary filesystems were removed. The supervision scenarios reaped their child processes, including the bounded timeout case.
- Synthetic guest identity `mips32le-execution-smoke.elf`: `c03d59d5f42ab3eb8e4afb388a1fe249d7f141a7897aac9f6de9d38b7598a423`. The QEMU binary identity matched the build/repeat result above. This session receipt reports `repeat_build_status=not-run`; reproducibility evidence is from the separate QEMU run #16 above.
- The synthetic runtime used a no-network, no-IPC guest container with all capabilities dropped, a read-only root filesystem, and bounded private temporary filesystems. QEMU user mode shares the host kernel; the hosted runner was not network-level egress isolated. This is firmware-free hosted Linux acceptance, not Windows/WSL2 validation or a dedicated-VM claim.

### Other exact-head CI

- Firmware-free M0 run [#87](https://github.com/wihlarkop/snowsky-disc-lab/actions/runs/39797080028): **completed / success**.
- Separate QEMU MIPS32LE execution smoke run [#29](https://github.com/wihlarkop/snowsky-disc-lab/actions/runs/39797079896): **skipped** by that workflow's branch guard; it had no executed jobs. The synthetic runtime acceptance above is the executed guest evidence.

These hosted results establish reproducible firmware-free build evidence and synthetic Linux runtime acceptance for the stated code head. They do not establish Windows/WSL2 behavior, redistribution clearance, or stock firmware compatibility.

## Remaining gates

- M1-01 remains open pending successful exact-head hosted build/repeat evidence and the wider M1 stock runtime acceptance.
- M1-07 remains open because WSL2 distro state, Docker Engine, Windows host details and the dedicated isolation boundary could not be verified from this CLI.
- M1-04 stock `mq_ui`/`mq_player`, proprietary firmware, hardware and device execution remain **NOT RUN / UNVERIFIED**.


## Bounded recheck on 2026-10-23 (M2-06 session)

Fresh diagnostics distinguish sandbox denial from host availability. The normal
Codex process ran with a Low Mandatory Level token, Administrators deny-only and
membership in docker-users. In that sandbox, WSL returned `Wsl/E_ACCESSDENIED`,
Docker denied access to its Linux Engine pipe, and CIM queries were refused.
These are permission failures, not proof that Docker Desktop is stopped.

A separately approved read-only diagnostic outside that sandbox reported:

| Observation | Measured result |
| --- | --- |
| OS | Windows 11 Home Single Language, 10.0.26200 |
| WSL | Default Ubuntu, version 2; Ubuntu/docker-desktop listed as stopped at the instant of the WSL listing |
| Docker context | desktop-linux |
| Client / server | 29.7.2 / 29.7.2; server replied successfully after the WSL listing |
| Desktop | 4.87.0 (236836) |
| Engine platform | linux/amd64; info architecture x86_64 |
| Engine resources | 8,242,479,104 bytes total memory, 12 CPUs |
| Engine security metadata | seccomp builtin, cgroupns |
| Host memory | 16,614,580 KiB visible; 3,053,684 KiB free at observation time |

The daemon was accessible in the approved diagnostic context. It was refused
inside the sandbox. The WSL stopped snapshot and later responding server are
separate observations; no stopped-Desktop diagnosis is inferred from them.
No ACL, daemon security, ownership or WSL configuration was changed.

The existing build requires at least 8 GiB **available** memory. Docker VM total
memory is already below that threshold, so no local QEMU rebuild was attempted.
No reusable measured runtime artifacts were imported from another session. Local
UI/QEMU/filesystem/IPC runtime acceptance is NOT RUN. This is a resource-gated
execution gap in addition to sandbox restrictions, not a guest test failure.
Docker Desktop metadata does not establish a dedicated trusted VM boundary for
stock firmware. M1-07 remains open; M1-04 remains NOT RUN / UNVERIFIED. Hosted
Linux execution is reported separately in the M2-06 evidence document.

## M1-07 operator diagnostic (2026-10-24 Jakarta)

Baseline: `15277ad12f85e6d297d93261d23d20d6055f3a64`. This preparation adds
`python -m snowsky_disc_lab.windows_readiness`; it complements `disc-lab doctor`
with failure classification and host/Engine resource observations. Doctor's
default behavior and CLI remain unchanged. This internal diagnostic JSON is an
observation, not a versioned acceptance receipt or an execution authorization.

From an ordinary Windows PowerShell in the reviewed checkout:

```powershell
uv run --locked python -m snowsky_disc_lab.windows_readiness
uv run --locked python -m snowsky_disc_lab.windows_readiness --wsl --docker-daemon
```

The first command reads only CIM logical CPU count, visible physical memory and
free physical memory. The second explicitly opts into `wsl --list --verbose`
(without launching a distribution) and a selected-field `docker info` query.
Docker uses the configured context, which **may be remote**; Engine resource
values must not be attributed to the Windows host without independent endpoint
review. No container, build, distribution start, filesystem write probe, mount,
firmware input, service configuration or device access is performed by the tool.
`uv` can create its normal development environment/cache; use an already prepared
environment's `python` directly when only diagnostic reads are wanted.

Each subprocess has a ten-second timeout. Output includes numeric resource
observations and distribution generation counts; distribution names, endpoint
paths, usernames and raw failure diagnostics are omitted. Raw localized messages
that cannot be recognized remain `query-failed`; do not infer a stopped daemon
or configuration error from that state. The fixed categories mean:

| Observation | Interpretation and next operator check |
| --- | --- |
| `access-denied` | This caller lacks access. Compare the same read-only command independently in the owner's ordinary shell; do not change ACLs, elevate Codex or disable its sandbox. This alone cannot identify which access policy denied the call. |
| `daemon-unavailable` | The configured Docker endpoint could not be reached. Check Docker Desktop/Engine status and the intended context manually; stopped Engine is one possibility, not a proven cause. |
| WSL `configuration-error` | A recognized optional-component, kernel, virtualization or missing-default-distro error was returned. Review the owner's WSL installation; the tool performs no repair. |
| `missing-tool`, `timed-out`, `unavailable`, `query-failed` | Observation could not finish; no resource or runtime inference is valid. |
| `invalid-observation` / WSL `unparsed` | Response cannot establish the expected resource values or distribution generations. Keep the gate open. |
| Host `insufficient` | Observed CPU/free-memory snapshot is below the build minimum. |
| Engine `insufficient` | Engine CPU count or **total** RAM is already below the build minimum. Available RAM cannot exceed total RAM. |
| Engine `available-memory-not-measured` | Total RAM clears the ceiling check; Linux `MemAvailable`, disk capacity and all other actual build guards still require measurement. |

Exit zero means the diagnostic finished reporting, including denied or unknown
observations. It never means readiness passed. `build_admitted` is false even
when the host's resource snapshot meets the minimum. Engine platform must be
`linux/amd64` for this existing build candidate. The unchanged build guard in
`scripts/ci/qemu_runtime_build.py` requires at least two CPUs and **8,589,934,592
bytes available RAM**, plus its disk/time/capacity checks. A regression binds
the diagnostic thresholds to that guard; this tool does not bypass or replace it.

### Fresh restricted-context result

The tool ran directly through the prepared Python environment in the default
Codex sandbox at **2026-10-23 17:32:15 UTC** (2026-10-24 00:32:15 Jakarta):

| Probe | Actual result |
| --- | --- |
| CIM host CPU/memory | `access-denied`; current numeric host resources unavailable |
| WSL distribution list | `access-denied`; current generation/state unavailable |
| Configured Docker Engine info | `access-denied`; current Engine CPU/memory unavailable |
| Trusted execution isolation | `unverified` |
| Windows runtime and stock execution | `not-run` |

No unrestricted or privileged diagnostic was requested or used in this wave.
The earlier independently observed **12 Engine CPUs / 8,242,479,104 bytes total
RAM** and host **16,614,580 KiB visible / 3,053,684 KiB free** above remain dated
observations, not refreshed measurements. That Engine total is approximately
7.68 GiB, below the 8 GiB **available** threshold even before any memory use.
No local rebuild was attempted. Keep the guard's refusal; changing memory
allocation or daemon configuration is outside this work.

For checks inaccessible here, the owner can run the two commands above
independently and review their sanitized output. To inspect failure details
privately, the equivalent read-only queries are:

```powershell
Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory
Get-CimInstance Win32_ComputerSystem | Select-Object NumberOfLogicalProcessors
wsl --status
wsl --list --verbose
docker info --format '{"cpus":{{json .NCPU}},"total_bytes":{{json .MemTotal}},"os":{{json .OSType}},"architecture":{{json .Architecture}}}'
```

The manual WSL commands expose distribution names; keep their output private.
Do not run setup, Compose up, QEMU, a WSL shell, a container memory probe or a
firmware extractor as a diagnostic substitute. This slice does not require a
QEMU rebuild to validate the diagnostic itself.

### Acceptance gate assessment

| Gate | State |
| --- | --- |
| Fixed read-only probes and sanitized classification | Implemented; firmware-free regressions cover denied/unavailable/configuration errors, UTF-16 WSL output, malformed data and resource refusal |
| Fresh Windows/WSL2/Engine resources | BLOCKED from this sandbox; owner commands provided |
| Existing local build memory guard | REFUSAL retained; earlier Engine total cannot satisfy its available-memory minimum |
| Windows firmware-free QEMU/input/IPC/cleanup acceptance | NOT RUN |
| Dedicated trusted VM, actual mount/network/process isolation | UNVERIFIED; Docker Desktop metadata cannot establish these properties |
| Stock V2.57 admission and M1-04 | BLOCKED / NOT RUN; firmware trust, extraction, identities and explicit later runtime authorization remain separate gates |
| M1-07 closure | OPEN; diagnostic preparation is not Windows runtime acceptance |

Hosted Linux build/synthetic results in the preceding sections remain historical
evidence for their exact code heads. The new PR's M0 Linux/Windows checks exercise
only firmware-free Python behavior; QEMU workflow branch guards may skip this
branch. Neither a skipped workflow nor synthetic comparator tests establish new
Windows QEMU or stock firmware acceptance.

Local validation for this slice used Windows Python 3.14.0 with locked project
dependencies: Ruff lint and formatting, locked `ty check`, and `git diff --check`
passed. The final full firmware-free suite passed **754 tests, 4 skipped** in
147.09 seconds; the skipped cases retain the existing platform/filesystem guards.
The new diagnostic's **24 regressions passed** separately. Existing warnings were
235 `PurePath.is_reserved` deprecations and one deliberate duplicate-ZIP-member
fixture warning. No schema/model contract changed; existing contract/parity
checks ran in the full suite. This verifies the tool and preserved regressions,
with live Windows probes limited to the denied observations recorded above.
