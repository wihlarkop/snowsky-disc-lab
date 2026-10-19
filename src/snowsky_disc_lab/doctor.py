"""Read-only host diagnostics; runtime, device, and network readiness stay unverified."""

from __future__ import annotations

import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
from dataclasses import dataclass
from pathlib import Path

from snowsky_disc_lab.host_platform import classify_host, normalize_architecture
from snowsky_disc_lab.sources import DEFAULT_CACHE_DIR, SourceError, _check_components

_CACHE_SPACE_ADVISORY = 10 * 1024**3
_MIN_DOCKER_ENGINE = (28, 1, 0)
_MIN_DOCKER_COMPOSE = (2, 36, 0)


@dataclass(frozen=True)
class Diagnostic:
    name: str
    status: str
    detail: str
    remediation: str = ""


def tool_version(name: str, arguments: tuple[str, ...]) -> Diagnostic:
    executable = shutil.which(name)
    if executable is None:
        return Diagnostic(
            name,
            "UNAVAILABLE",
            "not installed or absent from PATH",
            f"Install {name} or add it to PATH.",
        )
    try:
        result = subprocess.run(
            [executable, *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return Diagnostic(
            name,
            "UNAVAILABLE",
            "version query failed or timed out",
            f"Check that {name} runs from this shell.",
        )
    if result.returncode:
        return Diagnostic(
            name,
            "UNAVAILABLE",
            "version query returned an error",
            f"Check the {name} installation and PATH.",
        )
    # Only fixed version queries are executed; sanitize terminal control characters.
    detail = " ".join((result.stdout or result.stderr).split())[:200]
    detail = "".join(char for char in detail if char.isprintable())
    return Diagnostic(name, "AVAILABLE", detail or "version query succeeded")


def host_details() -> tuple[str, str, str]:
    # platform.uname() may fall back to a shell command on Windows. Avoid that path.
    if sys.platform == "win32":
        version = sys.getwindowsversion()
        return (
            "Windows",
            f"{version.major}.{version.minor}.{version.build}",
            sysconfig.get_platform(),
        )
    return platform.system(), platform.release(), platform.machine()


def _nearest_existing_directory(path: Path) -> Path:
    candidate = Path(os.path.abspath(os.fspath(path)))
    while True:
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            if candidate.parent == candidate:
                raise
            candidate = candidate.parent
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            if candidate.parent == candidate:
                raise OSError("no existing directory parent")
            candidate = candidate.parent
            continue
        return candidate


def _version_tuple(detail: str) -> tuple[int, int, int] | None:
    match = re.search(r"(?<!\d)(\d+)\.(\d+)(?:\.(\d+))?", detail)
    if match is None:
        return None
    return int(match[1]), int(match[2]), int(match[3] or 0)


def _version_text(version: tuple[int, int, int]) -> str:
    return ".".join(map(str, version))


def _cache_diagnostics(cache_root: Path, host_kind: str) -> list[Diagnostic]:
    rows: list[Diagnostic] = []
    parent: Path | None = None
    path_metadata_ok = False
    try:
        _check_components(cache_root, allow_missing_leaf=True)
        absolute_cache = Path(os.path.abspath(os.fspath(cache_root)))
        try:
            cache_metadata = absolute_cache.lstat()
        except FileNotFoundError:
            cache_metadata = None
        if cache_metadata is not None and not stat.S_ISDIR(cache_metadata.st_mode):
            raise SourceError("Selected source cache path is not a directory.")
        parent = _nearest_existing_directory(cache_root)
        path_metadata_ok = True
    except (OSError, SourceError):
        parent = None

    if path_metadata_ok and parent is not None:
        try:
            usage = shutil.disk_usage(parent)
            gib_free = usage.free / 1024**3
            disk_status = "AVAILABLE" if usage.free >= _CACHE_SPACE_ADVISORY else "WARNING"
            disk_detail = (
                f"{gib_free:.1f} GiB free on the selected cache volume; 10 GiB is an advisory "
                "threshold, not an M1 minimum."
            )
            rows.append(
                Diagnostic(
                    "Cache disk space",
                    disk_status,
                    disk_detail,
                    "Free space or select a larger volume; M1 storage needs measurement."
                    if disk_status == "WARNING"
                    else "The threshold is advisory; M1 storage requirements need measurement.",
                )
            )
        except OSError:
            rows.append(
                Diagnostic(
                    "Cache disk space",
                    "WARNING",
                    "could not inspect the nearest existing parent of the selected source cache.",
                    "Choose an existing local directory and check its volume manually.",
                )
            )
    else:
        rows.append(
            Diagnostic(
                "Cache disk space",
                "WARNING",
                "could not inspect the selected cache path or its nearest existing parent.",
                "Choose a valid directory path and check its volume manually.",
            )
        )

    if not path_metadata_ok or parent is None:
        rows.append(
            Diagnostic(
                "Cache permissions",
                "WARNING",
                "cache path metadata could not be inspected safely; no write probe.",
                "Inspect the path and its permissions before syncing sources.",
            )
        )
    else:
        try:
            readable = os.access(parent, os.R_OK | os.X_OK)
            writable = os.access(parent, os.W_OK | os.X_OK)
        except OSError:
            readable = writable = False
        status = "NOT VERIFIED" if readable and writable else "WARNING"
        detail = (
            "metadata and os.access indicate parent access; actual ACL and write capacity are "
            "NOT VERIFIED (no write probe)."
            if status == "NOT VERIFIED"
            else "metadata or os.access indicates limited access; actual ACL and write capacity "
            "are NOT VERIFIED (no write probe)."
        )
        rows.append(
            Diagnostic(
                "Cache permissions",
                status,
                detail,
                "Check read, write, and directory-traversal permissions if source sync fails.",
            )
        )

    normalized = os.path.abspath(os.fspath(cache_root))
    warnings: list[str] = []
    if host_kind == "native Windows" and len(normalized) >= 240:
        warnings.append("path is near the traditional Windows path-length boundary")
    if host_kind.startswith("WSL") and normalized.startswith("/mnt/"):
        warnings.append("cache is on a Windows-mounted path across the WSL filesystem boundary")
    rows.append(
        Diagnostic(
            "Cache path",
            "WARNING" if warnings or not path_metadata_ok else "AVAILABLE",
            "; ".join(warnings)
            if warnings
            else (
                "path metadata could not be inspected; no common-boundary claim can be made"
                if not path_metadata_ok
                else "no common Windows/WSL path-boundary issue detected from the path string"
            ),
            (
                "Choose a directory cache path and inspect parent components."
                if not path_metadata_ok
                else "Use a short WSL-native or Windows path if operations fail."
            ),
        )
    )
    absolute_cache = os.path.abspath(os.fspath(cache_root))
    printable_cache = "".join(character for character in absolute_cache if character.isprintable())
    rows.append(
        Diagnostic(
            "Source cache",
            "NOT VERIFIED",
            f"{printable_cache}; source contents and cache integrity are NOT VERIFIED.",
            (
                "Choose a directory for this cache path and inspect its parent components."
                if not path_metadata_ok
                else "Run `disc-lab sources verify` with the same lock and cache-dir settings."
            ),
        )
    )
    return rows


def _docker_engine_diagnostic(docker_daemon: bool) -> Diagnostic:
    if not docker_daemon:
        return Diagnostic(
            "Docker Engine",
            "NOT VERIFIED",
            "upstream QEMU documents Engine 28.1+; daemon version and Linux-container "
            "execution were not checked.",
            "Opt into `--docker-daemon` to query only the configured endpoint's server version; "
            "this still will not prove Linux-container execution.",
        )
    executable = shutil.which("docker")
    if executable is None:
        return Diagnostic(
            "Docker Engine",
            "UNAVAILABLE",
            "Docker CLI is not installed or absent from PATH.",
            "Install Docker CLI and configure an Engine endpoint.",
        )
    try:
        result = subprocess.run(
            [executable, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return Diagnostic(
            "Docker Engine",
            "UNAVAILABLE",
            "daemon query failed or timed out.",
            "Start or inspect the Docker Engine for the configured context.",
        )
    if result.returncode:
        return Diagnostic(
            "Docker Engine",
            "UNAVAILABLE",
            "daemon query returned an error.",
            "Start or inspect the Docker Engine for the configured context.",
        )
    version = " ".join(result.stdout.split())[:100]
    parsed = _version_tuple(version)
    if parsed is None:
        return Diagnostic(
            "Docker Engine",
            "NOT VERIFIED",
            "configured endpoint responded, but its server version could not be parsed; "
            "Linux-container execution was not checked.",
            "Check for Docker Engine 28.1+ and separately validate Linux-container execution.",
        )
    if parsed < _MIN_DOCKER_ENGINE:
        return Diagnostic(
            "Docker Engine",
            "WARNING",
            f"configured endpoint reports {_version_text(parsed)}; upstream QEMU documents "
            "28.1+; Linux-container execution is not proven.",
            "Update the configured Engine to 28.1+ and separately validate Linux containers.",
        )
    return Diagnostic(
        "Docker Engine",
        "AVAILABLE",
        f"configured endpoint reports server version {_version_text(parsed)}, meeting the "
        "upstream-documented 28.1+ minimum; the context may be remote, and Linux-container "
        "execution is not proven.",
        "Validate Linux-container execution and the selected host integration before M1.",
    )


def collect_diagnostics(
    cache_root: Path | None = None, *, docker_daemon: bool = False
) -> list[Diagnostic]:
    """Collect host/tool and cache diagnostics without starting services or writing files."""
    system, release, raw_architecture = host_details()
    host_kind = classify_host(system, release)
    architecture = normalize_architecture(raw_architecture)
    arch_status = "AVAILABLE" if architecture in {"x86_64", "arm64"} else "WARNING"
    host_status = (
        "WARNING" if host_kind not in {"native Windows", "native Linux", "WSL2"} else "AVAILABLE"
    )
    python_status = "AVAILABLE" if sys.version_info >= (3, 12) else "WARNING"
    git = tool_version("git", ("--version",))
    uv = tool_version("uv", ("--version",))
    rows = [
        Diagnostic(
            "Host",
            host_status,
            f"{host_kind}: {system} {release}",
            "Review the supported Windows 11/WSL2 or Linux host path before M1."
            if host_status == "WARNING"
            else "",
        ),
        Diagnostic(
            "Architecture",
            arch_status,
            f"{architecture} ({raw_architecture}); x86_64 and arm64 are candidate hosts; "
            "runtime compatibility is not verified.",
            "Use an x86_64 or arm64 candidate host, or review runtime support.",
        ),
        Diagnostic(
            "Python",
            python_status,
            f"{platform.python_version()} ({sys.implementation.name})",
            "Install Python 3.12 or newer to match the project requirement."
            if python_status == "WARNING"
            else "",
        ),
        Diagnostic("Git", git.status, git.detail, git.remediation),
        Diagnostic("uv", uv.status, uv.detail, uv.remediation),
    ]
    if system.casefold() == "windows":
        observed_version = _version_tuple(release)
        older_than_target = observed_version is not None and observed_version < (10, 0, 22000)
        rows.append(
            Diagnostic(
                "Windows target",
                "WARNING" if older_than_target else "NOT VERIFIED",
                "The observed build predates the Windows 11 target."
                if older_than_target
                else "An NT build alone cannot confirm Windows edition or target eligibility.",
                "Confirm Windows 11 and the WSL2/virtualization prerequisites manually before M1.",
            )
        )
    docker_cli = tool_version("docker", ("--version",))
    docker_compose = tool_version("docker", ("compose", "version"))
    compose_version = _version_tuple(docker_compose.detail)
    if docker_compose.status == "AVAILABLE" and compose_version is None:
        docker_compose = Diagnostic(
            "docker compose",
            "NOT VERIFIED",
            f"version command returned an unparseable value: {docker_compose.detail}",
            "Check for Docker Compose 2.36+ before M1.",
        )
    elif compose_version is not None and compose_version < _MIN_DOCKER_COMPOSE:
        docker_compose = Diagnostic(
            "docker compose",
            "WARNING",
            f"version {_version_text(compose_version)} is below the upstream QEMU documented "
            "minimum 2.36+.",
            "Update the Docker Compose plugin to 2.36+ before M1.",
        )
    else:
        compose_detail = docker_compose.detail
        compose_remediation = docker_compose.remediation
        if compose_version is not None and docker_compose.status == "AVAILABLE":
            compose_detail = (
                f"{compose_detail}; meets the upstream-documented 2.36+ minimum, which does not "
                "verify runtime compatibility."
            )
            compose_remediation = "Validate the pinned QEMU recipe before M1."
        docker_compose = Diagnostic(
            "docker compose",
            docker_compose.status,
            compose_detail,
            compose_remediation,
        )
    rows.extend(
        [
            Diagnostic("Docker CLI", docker_cli.status, docker_cli.detail, docker_cli.remediation),
            Diagnostic(
                "Docker Compose",
                docker_compose.status,
                docker_compose.detail,
                docker_compose.remediation,
            ),
            _docker_engine_diagnostic(docker_daemon),
        ]
    )
    if system.casefold() == "windows":
        wsl = tool_version("wsl", ("--version",))
        detail = (
            f"component query: {wsl.detail}; distribution and virtualization readiness are "
            "NOT VERIFIED"
        )
        rows.append(
            Diagnostic(
                "WSL components",
                "UNAVAILABLE" if wsl.status == "UNAVAILABLE" else "NOT VERIFIED",
                detail,
                "Install/update WSL2 and enable virtualization, then validate the selected "
                "distribution's Docker integration.",
            )
        )
    elif host_kind == "WSL2":
        rows.append(
            Diagnostic(
                "WSL components",
                "NOT VERIFIED",
                "kernel identifies WSL2; distribution integration and virtualization readiness "
                "are NOT VERIFIED.",
                "Verify WSL2 virtualization and Docker integration manually before M1.",
            )
        )
    elif host_kind == "WSL1":
        rows.append(
            Diagnostic(
                "WSL components",
                "WARNING",
                "kernel identifies WSL1; the target Windows route requires WSL2.",
                "Use a WSL2 distribution and verify its Docker integration before M1.",
            )
        )
    elif host_kind == "WSL generation NOT VERIFIED":
        rows.append(
            Diagnostic(
                "WSL components",
                "NOT VERIFIED",
                "Microsoft kernel release does not establish WSL1 versus WSL2.",
                "Confirm WSL2 and verify distribution/virtualization before M1.",
            )
        )
    else:
        rows.append(
            Diagnostic(
                "WSL components",
                "AVAILABLE",
                "WSL is a Windows-only component and is not required by this host.",
            )
        )
    rows.append(
        Diagnostic(
            "Pinned runtime/toolchain",
            "NOT VERIFIED",
            "future QEMU container/toolchain versions are not pinned; a native compiler is not "
            "required when a reviewed container provides it.",
            "Review and pin the QEMU runtime recipe and adapter toolchain before M1.",
        )
    )
    selected_cache = cache_root if cache_root is not None else Path.cwd() / DEFAULT_CACHE_DIR
    rows.extend(_cache_diagnostics(selected_cache, host_kind))
    rows.append(
        Diagnostic(
            "Runtime readiness",
            "NOT VERIFIED",
            "distribution, virtualization, container execution, and QEMU compatibility were not "
            "verified by these read-only checks.",
            "Review the M1 recipe and validate container integration before claiming readiness.",
        )
    )
    return rows
