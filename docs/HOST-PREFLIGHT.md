# Read-only host preflight

`uv run disc-lab doctor` reports observations and limitations for native Windows, WSL and native Linux. It extends the original M0 doctor and shares the source manager's cache setting. It does not certify a supported firmware/QEMU combination.

```sh
uv run disc-lab doctor
uv run disc-lab doctor --lock /path/to/upstreams.lock.yaml --cache-dir .lab/sources
```

`--lock` anchors the cache directory to the lock's parent, just as it does for source commands. Doctor does not read or validate that lock, require it to exist, verify source blobs, create the cache or sync anything. Run `sources verify --lock FILE` separately for source integrity.

The Docker version advisories below come from the [pinned upstream QEMU README](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/README.md). Changes to those prerequisites require a reviewed source/diagnostic update.

## Default checks

| Observation | Meaning and limits |
| --- | --- |
| Host and architecture | Describes native Windows/Linux or WSL kernel evidence and normalizes common CPU names. Windows builds older than the Windows 11 target warn; a build number alone does not establish edition/target eligibility. Candidate x86-64/ARM64 hosts remain distinct from a validated runtime. Ambiguous WSL evidence is not a proven WSL2 installation. |
| Python, Git and uv | Reports the running Python and fixed tool version queries. Python 3.12+ is the Lab baseline. No commands are installed, updated or executed from source repositories. |
| Docker CLI and Compose | Fixed client/component version queries only. The pinned upstream QEMU README documents Engine 28.1+ and Compose 2.36+; these are upstream requirements, not Lab-validated compatibility guarantees. A Docker client version does not prove an Engine is available or meets its requirement. |
| Windows WSL components | Queries `wsl --version` only. It does not enumerate or start distributions, enable virtualization, configure Windows features or prove the selected distribution uses WSL2. Inspect/install the intended WSL2 setup manually when required. |
| Cache disk space and path | Reads disk usage on the nearest safe existing parent without creating the selected directory. Low-space thresholds are advisory; exact M1 image/workspace needs remain unmeasured. Cache paths across Windows/WSL filesystems and long Windows paths may need attention. |
| Cache permissions | Reads metadata and access hints only. ACL effects, quotas, future disk pressure and actual write capacity remain NOT VERIFIED because no write probe is performed. A blocked/non-directory/unsafe path produces a warning. |
| Runtime/toolchain/readiness | Pinning and executing the future container/MIPS toolchain, distribution integration, Linux-container behavior and QEMU compatibility remain NOT VERIFIED. No native compiler is required merely to run this preflight. |

Each row gives a status and remediation/limit. `AVAILABLE` means the named observation succeeded; `UNAVAILABLE` means a queried tool/property could not be observed; `WARNING` identifies an observed limitation; `NOT VERIFIED` means no evidence was collected for that property. A complete diagnostic returns 0 even with unavailable/warning rows. Invalid command/path input returns 2. No aggregate “QEMU ready” result is emitted.

The default invokes only `git --version`, `uv --version`, `docker --version`, `docker compose version`, and, on native Windows, `wsl --version` when present in PATH. Calls have timeouts, capture output and do not use a shell. Missing tools and failed/timed-out queries produce diagnostics instead of tracebacks. There is no Docker daemon/network contact, service start/configuration, download, source execution, physical-device query or USB access. File access is metadata only; no scratch files or write probes are created.

## Explicit Docker daemon diagnostic

```sh
uv run disc-lab doctor --docker-daemon
```

This flag explicitly permits a fixed read-only Docker server-version query using the configured Docker context, which **may be remote**. It does not create/start containers or services, pull images, change context, configure sockets or execute guest code. A successful response establishes only that endpoint's version response. It does not certify Linux-container operation, mounts, runtime privileges, architecture or QEMU compatibility. The command does not print full daemon metadata, environment details or credential-bearing endpoints.

No opt-in daemon diagnostic is required by public CI. Local daemon acceptance and actual runtime checks must be recorded separately from default host preflight. See [trust boundaries and M1 gates](TRUST-BOUNDARIES.md).
