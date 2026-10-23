"""Opt-in Windows operator observations, never an execution admission receipt."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from typing import Any

# Mirror the existing build guard; a regression test binds these values to it.
MIN_CPUS = 2
MIN_AVAILABLE_MEMORY = 8 * 1024**3
_HOST_QUERY = (
    "$ErrorActionPreference='Stop'; "
    "$o=Get-CimInstance Win32_OperatingSystem; "
    "$c=Get-CimInstance Win32_ComputerSystem; "
    "@{cpus=$c.NumberOfLogicalProcessors; total_bytes=([long]$o.TotalVisibleMemorySize*1024); "
    "available_bytes=([long]$o.FreePhysicalMemory*1024)} | ConvertTo-Json -Compress"
)
_DOCKER_QUERY = (
    '{"cpus":{{json .NCPU}},"total_bytes":{{json .MemTotal}},'
    '"os":{{json .OSType}},"architecture":{{json .Architecture}}}'
)


def _decode(value: bytes) -> str:
    # WSL emits UTF-16LE on some Windows releases, including redirected output.
    encoding = "utf-16" if value.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8"
    if encoding == "utf-8" and b"\x00" in value:
        encoding = "utf-16-le"
    return value.decode(encoding, errors="replace")


def _query(tool: str, arguments: list[str]) -> tuple[str, str]:
    executable = shutil.which(tool)
    if executable is None:
        return "missing-tool", ""
    try:
        result = subprocess.run(
            [executable, *arguments], capture_output=True, timeout=10, check=False, shell=False
        )
    except PermissionError:
        return "access-denied", ""
    except subprocess.TimeoutExpired:
        return "timed-out", ""
    except OSError:
        return "unavailable", ""
    output = _decode(result.stdout)
    if result.returncode == 0:
        return "observed", output
    error = (output + _decode(result.stderr)).casefold()
    # Do not print raw endpoint paths, distribution names, user paths or stderr.
    if any(
        code in error
        for code in (
            "access is denied",
            "access denied",
            "e_accessdenied",
            "permission denied",
            "0x80070005",
            "0x80041003",
            "access to a cim resource was not available to the client",
        )
    ):
        return "access-denied", ""
    if tool == "wsl" and any(
        code in error
        for code in (
            "0x8007019e",
            "0x800701bc",
            "0x80370102",
            "wsl_e_wsl_optional_component_required",
            "wsl_e_virtualization_required",
            "wsl_e_default_distro_not_found",
        )
    ):
        return "configuration-error", ""
    if tool == "docker" and any(
        code in error
        for code in (
            "cannot connect",
            "connection refused",
            "system cannot find the file",
            "is not running",
        )
    ):
        return "daemon-unavailable", ""
    return "query-failed", ""


def _integer(value: Any) -> bool:
    return type(value) is int and 0 < value <= 2**63 - 1


def _resources(raw: str, *, docker: bool) -> dict[str, Any]:
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {"status": "invalid-observation"}
    if not isinstance(data, dict):
        return {"status": "invalid-observation"}
    required = ("cpus", "total_bytes") if docker else ("cpus", "total_bytes", "available_bytes")
    if not all(
        _integer(data.get(key))
        or (key == "available_bytes" and type(data.get(key)) is int and data[key] == 0)
        for key in required
    ):
        return {"status": "invalid-observation"}
    if not docker and data["available_bytes"] > data["total_bytes"]:
        return {"status": "invalid-observation"}
    result = {"status": "observed", **{key: data[key] for key in required}}
    if docker:
        if data.get("os") != "linux" or data.get("architecture") not in {"x86_64", "amd64"}:
            return {**result, "build_capacity": "unsupported-engine-platform"}
        result["platform"] = "linux/amd64"
    memory = data["total_bytes"] if docker else data["available_bytes"]
    result["build_capacity"] = (
        "insufficient"
        if data["cpus"] < MIN_CPUS or memory < MIN_AVAILABLE_MEMORY
        else "available-memory-not-measured"
        if docker
        else "snapshot-minimum-met"
    )
    # Docker total is only a ceiling. It cannot establish MemAvailable or disk capacity.
    result["build_admitted"] = False
    return result


def collect_observations(*, wsl: bool = False, docker_daemon: bool = False) -> dict[str, Any]:
    """Run fixed read-only probes; no distro launch, containers, writes or remediation."""
    report: dict[str, Any] = {
        "observed_at_utc": datetime.now(UTC).isoformat(),
        "scope": "windows-operator-observations",
        "minimum_build_cpus": MIN_CPUS,
        "minimum_build_available_memory_bytes": MIN_AVAILABLE_MEMORY,
        "trusted_execution_isolation": "unverified",
        "windows_runtime_acceptance": "not-run",
        "stock_execution": "not-run",
        "execution_authorized": False,
    }
    if sys.platform != "win32":
        return {**report, "host": {"status": "unsupported-host"}}
    status, raw = _query("powershell", ["-NoProfile", "-NonInteractive", "-Command", _HOST_QUERY])
    report["host"] = _resources(raw, docker=False) if status == "observed" else {"status": status}
    report["wsl"] = {"status": "not-requested"}
    if wsl:
        status, raw = _query("wsl", ["--list", "--verbose"])
        observation: dict[str, Any] = {"status": status}
        if status == "observed":
            versions = re.findall(r"\s([12])\s*$", raw, re.MULTILINE)
            observation = {
                "status": "observed" if versions else "unparsed",
                "wsl1_distribution_count": versions.count("1"),
                "wsl2_distribution_count": versions.count("2"),
                "selected_distribution_integration": "unverified",
            }
        report["wsl"] = observation
    report["docker_engine"] = {"status": "not-requested"}
    if docker_daemon:
        status, raw = _query("docker", ["info", "--format", _DOCKER_QUERY])
        report["docker_engine"] = (
            _resources(raw, docker=True) if status == "observed" else {"status": status}
        )
        report["docker_endpoint_scope"] = "configured-context-may-be-remote"
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--wsl", action="store_true", help="list distributions without starting them"
    )
    parser.add_argument(
        "--docker-daemon", action="store_true", help="query configured Engine (may be remote)"
    )
    args = parser.parse_args()
    print(
        json.dumps(collect_observations(wsl=args.wsl, docker_daemon=args.docker_daemon), indent=2)
    )


if __name__ == "__main__":
    main()
