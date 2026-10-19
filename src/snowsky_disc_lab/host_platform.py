"""Small, side-effect-free host classification helpers."""

from __future__ import annotations


def classify_host(system: str, release: str) -> str:
    """Describe the observed OS boundary without asserting runtime readiness."""
    if system.casefold() == "windows":
        return "native Windows"
    if system.casefold() == "linux":
        normalized_release = release.casefold()
        if "microsoft" in normalized_release:
            if "wsl2" in normalized_release or "microsoft-standard" in normalized_release:
                return "WSL2"
            if normalized_release.startswith("4.4."):
                return "WSL1"
            return "WSL generation NOT VERIFIED"
        return "native Linux"
    return f"{system or 'unknown'} host"


def normalize_architecture(architecture: str) -> str:
    """Normalize common machine aliases to candidate host architectures."""
    value = architecture.casefold().replace("-", "_")
    if value in {"amd64", "x64", "x86_64", "win_amd64"}:
        return "x86_64"
    if value in {"arm64", "aarch64", "win_arm64"}:
        return "arm64"
    return architecture or "unknown"
