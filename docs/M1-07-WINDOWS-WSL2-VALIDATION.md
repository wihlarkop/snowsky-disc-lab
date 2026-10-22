# M1-01 Runtime Reproducibility and M1-07 Windows/WSL2 Validation

**Assessment date:** 2026-10-22
**Repository baseline:** `3625df30805f570c148fccc6bf6d928de7d6795e`
**Status:** M1-01 and M1-07 remain open. M1-04 stock firmware execution remains **NOT RUN / UNVERIFIED**.

## Runtime build verification changes

The existing pinned QEMU build pipeline remains the source of build evidence. The build receipt is now rejected unless it contains complete, internally consistent identities for the five static ELF artifacts, signed Debian snapshot metadata, archive keyring, canonical installed-package BOM, fakeroot bootstrap package hashes, native and MIPS toolchain versions and executable hashes, MIPS sysroot tree, reviewed input manifest, configure flags, build logs, container limits and output retention. The host compares the returned manifest digest with the digest it prepared before accepting the receipt.

Independent clean builds now compare those identities and full artifact records. Missing or unknown evidence is an error; an incomplete comparison cannot be called `identical`. Repeat statuses are explicit. A differing or attempted-but-failed repeat makes the build command fail. A resource- or time-gated repeat remains `not-run`, with its reason recorded; it is not reported as reproducible.

The existing firmware-free acceptance remains the implementation under test. The pull request CI runs the QEMU build/repeat workflow and the existing synthetic runtime session workflow. Hosted Linux results must be read from the exact pull request head and appended here before this report is considered complete.

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

**Pending exact pull request CI.** Record the PR head SHA, workflow run IDs and conclusions, first and second build artifact SHA-256 values, package BOM and sysroot digests, and repeat status after the workflows finish. Do not mark a `not-run` repeat reproducible. These hosted results do not establish Windows/WSL2 behavior or stock firmware compatibility.

## Remaining gates

- M1-01 remains open pending successful exact-head hosted build/repeat evidence and the wider M1 stock runtime acceptance.
- M1-07 remains open because WSL2 distro state, Docker Engine, Windows host details and the dedicated isolation boundary could not be verified from this CLI.
- M1-04 stock `mq_ui`/`mq_player`, proprietary firmware, hardware and device execution remain **NOT RUN / UNVERIFIED**.
