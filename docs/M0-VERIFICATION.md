# Issue #1 verification and limits

Scope: M0-01, M0-03 and minimal M0-06. The foundation supplies Python packaging, host/tool diagnostics, schema-only manifests, generated JSON Schema, synthetic fixtures and firmware-free CI. Source locks/cache resolution and emulator/runtime integration are deferred.

## Reproduce

```sh
uv sync --dev
uv run disc-lab --help
uv run disc-lab doctor
uv run disc-lab ui validate examples/ui-valid.yaml
uv run disc-lab firmware validate examples/firmware-valid.yaml
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run pytest
```

Use `uv sync --locked --dev` to additionally refuse dependency-lock drift. Tool versions are pinned by `uv.lock`. This sandbox uses `UV_CACHE_DIR=<checkout>/.cache/uv`; pytest scratch space is configured as `.cache/pytest` (owned by pytest and cleared between runs).

## Acceptance boundaries

Local verification on Windows x86-64 / CPython 3.14.0 (free-threaded): `uv sync --locked --dev`, both Ruff commands, `ty check`, CLI help, real `doctor` version reporting and both good fixture commands passed. `uv run pytest`: **51 passed, 1 skipped**. The skipped POSIX FIFO case requires Linux; Windows symlink escape coverage passed. Missing Docker is covered by a simulated unavailable-tool regression. Hosted Linux/Windows Python matrix results are recorded on the Draft PR.

CLI/contract tests cover valid UI and firmware fixtures, missing files/fields, malformed YAML, unsupported API versions, unknown keys/presets, architecture/device mismatch, strict string/hash/revision checks, safe relative paths and symlink containment. Public schemas are compared against model output. Host tests simulate missing tools, failed/timed-out version queries and allowlist fixed commands. Validation does not open the declared UI output or use firmware files.

The workflow targets Linux and Windows on Python 3.12 and 3.14, uses read-only repository permission, immutable action commits and no credential persistence, secrets, firmware, devices, dependency cache sharing or privileged containers. Hosted results belong to the PR's exact commit, not to local test results.

All firmware-backed, QEMU, WSL2/Docker runtime, UI binary build/ELF inspection, performance, legacy firmware and physical-device acceptance: **NOT RUN**. Their commands are not implemented. No vendor files, user media, keys, upstream code or device dumps were introduced. No device access or flashing occurred. Schema success cannot establish vendor authenticity or verified compatibility.

Core licensing/SPDX inventory and the wider M0-04/M0-06/M0-07 work remain pending as described in the roadmap. Next single milestone: **M0-02 + M0-05**, immutable upstream locks and offline source-cache verification, before M1 stock V2.57.
