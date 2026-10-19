"""Read-only host diagnostics; never contact the Docker daemon or network."""

import platform
import shutil
import subprocess
import sys
import sysconfig
from dataclasses import dataclass


@dataclass(frozen=True)
class Diagnostic:
    name: str
    status: str
    detail: str


def tool_version(name: str, arguments: tuple[str, ...]) -> Diagnostic:
    executable = shutil.which(name)
    if executable is None:
        return Diagnostic(name, "UNAVAILABLE", "not installed or absent from PATH")
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
        return Diagnostic(name, "UNAVAILABLE", "version query failed or timed out")
    if result.returncode:
        return Diagnostic(name, "UNAVAILABLE", "version query returned an error")
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


def collect_diagnostics() -> list[Diagnostic]:
    system, release, architecture = host_details()
    rows = [
        Diagnostic("Host", "INFO", f"{system} {release} / {architecture}"),
        Diagnostic(
            "Python", "AVAILABLE", f"{platform.python_version()} ({sys.implementation.name})"
        ),
        tool_version("docker", ("--version",)),
        tool_version("docker", ("compose", "version")),
    ]
    rows[2] = Diagnostic("Docker CLI", rows[2].status, rows[2].detail)
    rows[3] = Diagnostic("Docker Compose", rows[3].status, rows[3].detail)
    if system == "Windows":
        # --version reports installed WSL components; never enumerate/start distributions.
        rows.append(tool_version("wsl", ("--version",)))
    elif system == "Linux":
        is_wsl = "microsoft" in release.lower()
        rows.append(Diagnostic("WSL", "INFO", "WSL host detected" if is_wsl else "not detected"))
    else:
        rows.append(Diagnostic("WSL", "NOT APPLICABLE", "Windows-only prerequisite"))
    return rows
