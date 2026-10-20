#!/usr/bin/env python3
"""Bounded firmware-free QEMU runtime build checks for the hosted PR runner."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "docs" / "m1-01-runtime-preparation.json"
UPSTREAM = "https://github.com/eudj1n/snowsky-disc-qemu.git"
UPSTREAM_COMMIT = "85ab00deb08ac112066377fd8083cc8727ed859a"
SOURCE_PROJECTION_DIGEST = "ef1f0b45f86d4724a7359694b2c3bc4c"
BASE_IMAGE = (
    "docker.io/library/debian:12@sha256:"
    "6ebd97fa83deb272194a2cf015b3d26a4d538e9ad3a7a79d544c8af5b0a01443"
)
BASE_INDEX_SHA256 = "6ebd97fa83deb272194a2cf015b3d26a4d538e9ad3a7a79d544c8af5b0a01443"
BASE_AMD64_MANIFEST = "2f65600e1252c5649d2213e1d1ea4d74253d26514dc6530102a875e429245929"
QEMU_VERSION = "1:7.2+dfsg-7+deb12u18"
QEMU_DSC_SHA256 = "6b6bd27b947ec89e40a1d6b26d9c9f3c698ca691da13163e0483f6061bbb20b3"
QEMU_ARCHIVES = {
    "qemu_7.2+dfsg.orig.tar.xz": (
        23_523_172,
        "91aca71520040edc40b8d437aa3004dae614f58e286cf653ee8996c07af2962f",
    ),
    "qemu_7.2+dfsg-7+deb12u18.debian.tar.xz": (
        405_636,
        "28a1c86310ee53b6bf1854cffe6f6be6ed29a08db7d05759f8ac57b8d6a6cb2f",
    ),
}
DEBIAN_SIGNING_FINGERPRINTS = {
    "bookworm": "4CB50190207B4758A3F73A796ED0E7B82643E131",
    "bookworm-updates": "4CB50190207B4758A3F73A796ED0E7B82643E131",
    "bookworm-security": "ED541312A33F1128F10B1C6C54404762BBB6E853",
}
REVIEWED_SOURCE_IDENTITIES = {
    "LICENSE": (
        "4062ec7aefe2cff17e61c5bc1e892a073aa9640f",
        "8cbb19ad3535601695a5c40583497c5e1bcbb8fddaf0e177be07a54cf15e8762",
    ),
    "emulator/docker/Dockerfile": (
        "8180facedbb4f2a6e0048f2fafc1f0dea36e4416",
        "1de02256f4c2afdb68f854a63293ed651d4aec28c979d2e4ab154a41ed1591b0",
    ),
    "emulator/docker/debian.sources": (
        "65aaafc20db4027d7a0404ab43985a940fa64c6c",
        "296362819b78fc90449f2e020f89986c3d3edd2e53fc1d427e572d5209fd595a",
    ),
    "emulator/docker/qemu/snowsky-disc-devices.patch": (
        "e6e876bb69475e2cb90aa389b44758bcb02bd66a",
        "f3cfebb2eac8170f724b5d5ca900e857fbdfd8905fd1fb4aedc6bcdf41cf3895",
    ),
    "emulator/shims/asndshim.c": (
        "bc01ff258e421d7aad1986a3ada1f62b311b4b95",
        "3c40915af5c55f20f261923dd48f93aee14a4dfdc3c117c7673ede1daefb8d2f",
    ),
    "emulator/shims/asound.cards": (
        "1f514c70c462f68f0b4482eba6d72bac8374be27",
        "a9543fb9955047fb92d926531f3334403d4ffa995d3c7307d7ffa8b9d2d0e099",
    ),
    "emulator/shims/build_shims.sh": (
        "d389669d073d9b31ede635c2743ab4fa758948ab",
        "81672b21c54e8757a4ca95e0abedeeef17d4dda2300995b3f62a0fe17d24a838",
    ),
    "emulator/shims/capture.h": (
        "ea4324c49017f1c3ff88bfc9fdb4720631c446b1",
        "bcbf9357e73ce1022cbd03af4da4d064a82adf3278bcbc51dee416798f8ba740",
    ),
    "emulator/shims/fbshim.c": (
        "87eb5adcbd081582a995018a06de0139fab0f3c5",
        "363c84afa84f3aac9738df1d8f232ca5e2ee5b2ae530acf35fe0e6b132cc64a8",
    ),
    "emulator/shims/mqshim.c": (
        "ffb75e62d167e91b980f5ace610c402b86e8f6f3",
        "41ea965dd0bb06ae6dfdedeb7a30af267df7393aaa6770bb0aa19ea4bbdb1bb5",
    ),
    "emulator/shims/tinyshim.c": (
        "a433e98f8ffb94afaac1f24804019f39b49eb94c",
        "ff290becc5d431f8594da8d401cf424f18abcf652020211014b9a06573c93cc1",
    ),
}
MIN_CPUS = 2
MIN_AVAILABLE_MEMORY = 8 * 1024**3
MIN_DOCKER_FREE = 10 * 1024**3
MIN_TEMP_FREE = 1 * 1024**3
AUDIT_EVIDENCE_FILES = (
    ("/audit/inrelease.tsv", "inrelease.tsv"),
    ("/audit/archive-keyring-before.sha256", "archive-keyring-before.sha256"),
    (
        "/audit/source/qemu_7.2+dfsg-7+deb12u18.dsc",
        "source/qemu_7.2+dfsg-7+deb12u18.dsc",
    ),
    (
        "/audit/source/qemu_7.2+dfsg.orig.tar.xz",
        "source/qemu_7.2+dfsg.orig.tar.xz",
    ),
    (
        "/audit/source/qemu_7.2+dfsg-7+deb12u18.debian.tar.xz",
        "source/qemu_7.2+dfsg-7+deb12u18.debian.tar.xz",
    ),
    ("/audit/unpacked/debian/copyright", "unpacked/debian/copyright"),
    ("/audit/copying-hashes.txt", "copying-hashes.txt"),
)
AUDIT_LOG_FILES = tuple(
    (f"/audit/{name}", name)
    for name in (
        "apt-update.log",
        "apt-install.log",
        "fakeroot-bootstrap.tsv",
        "source-download.log",
        "source-extract.log",
    )
)
AUDIT_LOG_FILES += (
    ("/audit/phase", "phase"),
    ("/audit/failure-log", "failure-log"),
    ("/audit/input-hash-check.log", "input-hash-check.log"),
    ("/audit/patch-application.log", "patch-application.log"),
    ("/audit/qemu-configure.log", "qemu-configure.log"),
    ("/audit/qemu-build.log", "qemu-build.log"),
    ("/audit/shim-build.log", "shim-build.log"),
)
FAKEROOT_BOOTSTRAP_PACKAGES = ("fakeroot-sysv", "libfakeroot")
NATIVE_BUILD_PACKAGES = (
    "dpkg-dev",
    "build-essential",
    "ninja-build",
    "meson",
    "python3",
    "pkg-config",
    "libglib2.0-dev",
    "libpcre2-dev",
    "zlib1g-dev",
    "libffi-dev",
    "libmount-dev",
    "libblkid-dev",
    "libselinux1-dev",
    "libcap-ng-dev",
    "libattr1-dev",
    *FAKEROOT_BOOTSTRAP_PACKAGES,
)
CROSS_SHIM_PACKAGES = (
    "gcc-mipsel-linux-gnu",
    "binutils-mipsel-linux-gnu",
    "libc6-dev-mipsel-cross",
)
QEMU_CONFIGURE_FLAGS = (
    "--static",
    "--disable-system",
    "--disable-tools",
    "--disable-guest-agent",
    "--disable-docs",
    "--disable-werror",
    "--target-list=mipsel-linux-user",
    "--with-pkgversion=Debian 1:7.2+dfsg-7+deb12u18, snowsky-disc-devices",
)
BUILD_EVIDENCE_FILES = (("/audit/build-evidence.json", "build-evidence.json"),)
BUILD_EVIDENCE_MAX_BYTES = 1024 * 1024
EXPECTED_BUILD_ARTIFACTS = {
    "qemu-mipsel",
    "fbshim.so",
    "asndshim.so",
    "tinyshim.so",
    "mqshim.so",
}
AUDIT_FILE_MAX_BYTES = {
    "inrelease.tsv": 4 * 1024,
    "archive-keyring-before.sha256": 128,
    "source/qemu_7.2+dfsg-7+deb12u18.dsc": 1024 * 1024,
    "source/qemu_7.2+dfsg.orig.tar.xz": QEMU_ARCHIVES["qemu_7.2+dfsg.orig.tar.xz"][0],
    "source/qemu_7.2+dfsg-7+deb12u18.debian.tar.xz": QEMU_ARCHIVES[
        "qemu_7.2+dfsg-7+deb12u18.debian.tar.xz"
    ][0],
    "unpacked/debian/copyright": 4 * 1024 * 1024,
    "copying-hashes.txt": 128 * 1024,
    "build-evidence.json": BUILD_EVIDENCE_MAX_BYTES,
    **{name: 1024 * 1024 for _, name in AUDIT_LOG_FILES},
}


class StopBuild(RuntimeError):
    """A reviewed prerequisite did not pass; the build must stop."""


def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    capture: bool = False,
    check: bool = True,
    timeout: int = 300,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        timeout=timeout,
    )
    if check and result.returncode:
        detail = (result.stdout or "").strip()
        raise StopBuild(
            f"command failed ({result.returncode}): {args[0]} {args[1]}"
            + (f"; {detail[-800:]}" if detail else "")
        )
    return result


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def read_reference() -> dict[str, Any]:
    reference = json.loads(REFERENCE.read_text(encoding="utf-8"))
    integration_source = reference.get("integrationSource", {})
    if (
        integration_source.get("commit") != UPSTREAM_COMMIT
        or integration_source.get("projectionDigest") != SOURCE_PROJECTION_DIGEST
        or integration_source.get("sourceLockChanged") is not False
    ):
        raise StopBuild("M1-01 QEMU source identity differs from the workflow pin")
    inputs = reference.get("buildInputs", {})
    if tuple(inputs.get("nativeBuildPackageRequests", [])) != NATIVE_BUILD_PACKAGES:
        raise StopBuild("M1-01 QEMU build package requests differ from the reviewed set")
    package_strategy = inputs.get("packageInstallStrategy", {})
    if (
        package_strategy.get("installer") != "fakeroot"
        or tuple(package_strategy.get("bootstrapPackages", [])) != FAKEROOT_BOOTSTRAP_PACKAGES
        or package_strategy.get("containerCapabilities") != "all dropped"
    ):
        raise StopBuild("M1-01 capability-free package installation strategy changed")
    shim = inputs.get("shimToolchain", {})
    if tuple(shim.get("packages", [])) != CROSS_SHIM_PACKAGES:
        raise StopBuild("M1-01 shim toolchain package requests differ from the reviewed set")
    if shim.get("recipe") != "emulator/shims/build_shims.sh":
        raise StopBuild("M1-01 shim build recipe identity changed")
    if inputs.get("baseImage", {}).get("reference") != BASE_IMAGE:
        raise StopBuild("M1-01 base image reference differs from the workflow pin")
    if inputs.get("baseImage", {}).get("platformManifest") != f"sha256:{BASE_AMD64_MANIFEST}":
        raise StopBuild("M1-01 amd64 base manifest differs from the workflow pin")
    qemu = inputs.get("qemu", {})
    if (
        qemu.get("debianSourceVersion") != QEMU_VERSION
        or qemu.get("sourceDescriptor", {}).get("sha256") != QEMU_DSC_SHA256
        or tuple(qemu.get("configureFlags", [])) != QEMU_CONFIGURE_FLAGS
    ):
        raise StopBuild(
            "M1-01 Debian QEMU source or configure identity differs from the workflow pin"
        )
    reference_archives = {
        item["name"]: (item["bytes"], item["sha256"]) for item in qemu.get("sourceArchives", [])
    }
    if reference_archives != QEMU_ARCHIVES:
        raise StopBuild("M1-01 QEMU source archive checksums differ from the workflow pins")
    snapshots = inputs.get("debianSnapshots", {})
    if snapshots.get("timestamp") != "20260910T000000Z":
        raise StopBuild("M1-01 Debian snapshot timestamp differs from the workflow pin")
    return reference


def resource_report() -> dict[str, Any]:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise StopBuild("runner must be Linux x86_64")
    release = Path("/etc/os-release").read_text(encoding="utf-8")
    if not re.search(r"(?m)^ID=ubuntu$", release) or not re.search(
        r'(?m)^VERSION_ID="?24\.04"?$', release
    ):
        raise StopBuild("runner must be Ubuntu 24.04")

    cpu_result = run(["nproc"], capture=True)
    cpus = int((cpu_result.stdout or "0").strip())
    memory = {}
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        key, _, value = line.partition(":")
        if key in {"MemTotal", "MemAvailable"}:
            memory[key] = int(value.strip().split()[0]) * 1024

    workspace_free = shutil.disk_usage(ROOT).free
    temp_free = shutil.disk_usage(tempfile.gettempdir()).free
    docker_free = None
    docker_version = None
    buildx_version = None
    docker_error = None
    try:
        docker_info = run(
            ["docker", "info", "--format", "{{.DockerRootDir}}"], capture=True, timeout=60
        )
        docker_root = Path((docker_info.stdout or "").strip())
        if not docker_root.is_absolute() or not docker_root.exists():
            raise StopBuild("Docker daemon reported an invalid storage directory")
        docker_free = shutil.disk_usage(docker_root).free
        version = run(
            ["docker", "version", "--format", "{{.Server.Version}}"], capture=True, timeout=60
        )
        buildx = run(["docker", "buildx", "version"], capture=True, timeout=60)
        docker_version = (version.stdout or "").strip()
        buildx_version = (buildx.stdout or "").strip()
    except (StopBuild, OSError) as exc:
        docker_error = str(exc)[:300]

    report = {
        "runner": "ubuntu-24.04",
        "architecture": "x86_64",
        "cpus_available": cpus,
        "memory_total_bytes": memory.get("MemTotal"),
        "memory_available_bytes": memory.get("MemAvailable"),
        "workspace_free_bytes": workspace_free,
        "temporary_storage_free_bytes": temp_free,
        "docker_free_bytes": docker_free,
        "docker_server_version": docker_version,
        "docker_buildx_version": buildx_version,
        "docker_error": docker_error,
        "estimated_requirements": {
            "minimum_cpus": MIN_CPUS,
            "minimum_available_memory_bytes": MIN_AVAILABLE_MEMORY,
            "minimum_docker_free_bytes": MIN_DOCKER_FREE,
            "minimum_temporary_storage_free_bytes": MIN_TEMP_FREE,
            "basis": (
                "Estimate for the pinned QEMU source build and cross-toolchain packages "
                "with temporary build storage and 2 GiB disk headroom; no runtime image."
            ),
        },
    }
    failures = []
    if cpus < MIN_CPUS:
        failures.append("fewer than 2 available CPUs")
    if memory.get("MemAvailable", 0) < MIN_AVAILABLE_MEMORY:
        failures.append("less than 8 GiB available memory")
    if temp_free < MIN_TEMP_FREE:
        failures.append("less than 1 GiB free temporary storage")
    if docker_error is not None:
        failures.append("Docker daemon or Buildx unavailable")
    if docker_free is not None and docker_free < MIN_DOCKER_FREE:
        failures.append("less than 10 GiB free Docker storage")
    report["capacity_status"] = "sufficient" if not failures else "insufficient"
    report["capacity_failures"] = failures
    return report


def fetch_reviewed_upstream(
    workdir: Path, reference: dict[str, Any]
) -> tuple[Path, dict[str, str], dict[str, int]]:
    checkout = workdir / "upstream"
    checkout.mkdir()
    evidence = {
        item["path"]: (item.get("gitBlob"), item.get("sha256"))
        for item in reference["evidenceFiles"]
        if item["path"].startswith(("emulator/docker/", "emulator/shims/"))
        or item["path"] == "LICENSE"
    }
    if evidence != REVIEWED_SOURCE_IDENTITIES:
        raise StopBuild("M1-01 Docker/shim source inventory or immutable hashes changed")

    allowed_hosts = {"raw.githubusercontent.com", "github.com", "objects.githubusercontent.com"}

    class GitHubRedirects(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
            parsed = urlparse(newurl)
            if parsed.scheme != "https" or parsed.hostname not in allowed_hosts:
                raise StopBuild(
                    "GitHub source request redirected outside the approved GitHub endpoints"
                )
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = build_opener(GitHubRedirects())
    hashes: dict[str, str] = {}
    sizes: dict[str, int] = {}
    for relative, (expected_blob, expected_sha256) in sorted(REVIEWED_SOURCE_IDENTITIES.items()):
        posix_path = PurePosixPath(relative)
        if (
            posix_path.is_absolute()
            or ".." in posix_path.parts
            or "\\" in relative
            or posix_path.as_posix() != relative
        ):
            raise StopBuild("reviewed upstream path is not a normalized relative path")
        url = (
            "https://raw.githubusercontent.com/eudj1n/snowsky-disc-qemu/"
            f"{UPSTREAM_COMMIT}/{quote(relative, safe='/')}"
        )
        try:
            with opener.open(
                Request(url, headers={"User-Agent": "snowsky-disc-lab-qemu-preflight"}), timeout=60
            ) as response:
                final = urlparse(response.geturl())
                if final.scheme != "https" or final.hostname not in allowed_hosts:
                    raise StopBuild("GitHub source request reached an unapproved endpoint")
                declared_size = response.headers.get("Content-Length")
                if declared_size and int(declared_size) > 4 * 1024 * 1024:
                    raise StopBuild(f"reviewed source exceeds the 4 MiB file bound: {relative}")
                content = response.read(4 * 1024 * 1024 + 1)
        except HTTPError as exc:
            raise StopBuild(
                f"GitHub source request returned HTTP {exc.code} for {relative}"
            ) from exc
        except URLError as exc:
            raise StopBuild(f"GitHub source request failed for {relative}: {exc.reason}") from exc
        if len(content) > 4 * 1024 * 1024:
            raise StopBuild(f"reviewed source exceeds the 4 MiB file bound: {relative}")
        actual = hashlib.sha256(content).hexdigest()
        blob = hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()
        if actual != expected_sha256 or blob != expected_blob:
            raise StopBuild(f"reviewed source identity mismatch: {relative}")
        path = checkout / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        hashes[relative] = actual
        sizes[relative] = len(content)
    return checkout, hashes, sizes


def verify_base_image() -> dict[str, Any]:
    raw = run(
        ["docker", "buildx", "imagetools", "inspect", "--raw", BASE_IMAGE],
        capture=True,
        timeout=120,
    ).stdout
    actual_index = hashlib.sha256(raw.rstrip("\r\n").encode()).hexdigest()
    if actual_index != BASE_INDEX_SHA256:
        raise StopBuild("registry manifest bytes do not match the pinned Debian index digest")
    index = json.loads(raw)
    amd64 = [
        item
        for item in index.get("manifests", [])
        if item.get("platform", {}).get("os") == "linux"
        and item.get("platform", {}).get("architecture") == "amd64"
    ]
    if len(amd64) != 1 or amd64[0].get("digest") != f"sha256:{BASE_AMD64_MANIFEST}":
        raise StopBuild("Debian amd64 platform manifest does not match the pinned identity")
    run(["docker", "pull", "--platform", "linux/amd64", BASE_IMAGE], timeout=180)
    image = json.loads(run(["docker", "image", "inspect", BASE_IMAGE], capture=True).stdout)[0]
    if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
        raise StopBuild("pulled base image is not linux/amd64")
    return {
        "reference": BASE_IMAGE,
        "index_digest": f"sha256:{actual_index}",
        "platform_manifest": amd64[0]["digest"],
        "local_config_digest": image.get("Id"),
        "platform": f"{image.get('Os')}/{image.get('Architecture')}",
    }


def source_audit_container(sources_file: Path, audit_dir: Path) -> None:
    audit_dir.mkdir(parents=True, exist_ok=True)
    (audit_dir / "source").mkdir(exist_ok=True)
    source_text = sources_file.read_text(encoding="utf-8")
    if source_text.count("Types: deb\n") != 2:
        raise StopBuild("reviewed Debian source file no longer matches the expected two entries")
    prepared_sources = audit_dir / "debian.sources"
    prepared_sources.write_text(
        source_text.replace("Types: deb\n", "Types: deb deb-src\n"), encoding="utf-8"
    )
    archive_checks = "\n".join(
        f"test \"$(stat -c %s '/audit/source/{name}')\" -eq {size}\n"
        f"printf '%s  %s\\n' '{sha256}' '/audit/source/{name}' | sha256sum --check --status"
        for name, (size, sha256) in QEMU_ARCHIVES.items()
    )
    signature_case = "\n".join(
        f"    {suite}) expected_fingerprint='{fingerprint}' ;;"
        for suite, fingerprint in DEBIAN_SIGNING_FINGERPRINTS.items()
    )
    command = (
        r"""
set -eEuo pipefail
exec 3>&2
install -d -m 0700 /audit
phase=container-initialization
failure_log=
report_failure() {
  failure_status=$?
  trap - ERR
  printf 'FIRMWARE_FREE_PHASE_FAILURE phase=%s exit=%s\n' "$phase" "$failure_status" >&3
  if [[ -n "$failure_log" && -f "$failure_log" ]]; then
    printf '%s\n' 'FIRMWARE_FREE_LOG_TAIL_BEGIN' >&3
    tail -n 12 "$failure_log" | sed -E 's/[[:cntrl:]]/ /g' | cut -c1-500 >&3
    printf '%s\n' 'FIRMWARE_FREE_LOG_TAIL_END' >&3
  fi
  exit "$failure_status"
}
trap report_failure ERR
mark_phase() {
  phase="$1"
  failure_log="$2"
  printf '%s\n' "$phase" > /audit/phase
  printf '%s\n' "$failure_log" > /audit/failure-log
}
mark_phase container-initialization ""
export DEBIAN_FRONTEND=noninteractive
apt_opts=(
  -o APT::Sandbox::User=root
  -o Dpkg::Use-Pty=false
  -o Dir::Log=/dev/null
  -o Dir::Etc::sourcelist=/dev/null
  -o Dir::Etc::sourceparts=/etc/apt/sources.list.d
  -o Acquire::Languages=none
  -o Acquire::AllowInsecureRepositories=false
  -o Acquire::AllowDowngradeToInsecureRepositories=false
  -o Acquire::AllowWeakRepositories=false
  -o APT::Get::AllowUnauthenticated=false
)
test ! -e /etc/apt/sources.list
source_files=(/etc/apt/sources.list.d/*)
test "${#source_files[@]}" -eq 1
test "${source_files[0]}" = /etc/apt/sources.list.d/debian.sources
mark_phase debian-index-update /audit/apt-update.log
apt-get "${apt_opts[@]}" update >/audit/apt-update.log 2>&1
keyring=/usr/share/keyrings/debian-archive-keyring.gpg
sha256sum "$keyring" | awk '{print $1}' > /audit/archive-keyring-before.sha256
mark_phase debian-signature-verification /audit/apt-update.log
for f in /var/lib/apt/lists/*_InRelease; do
  status="$(gpgv --status-fd 1 --keyring "$keyring" "$f" 2>&1)"
  fingerprint="$(printf '%s\n' "$status" | awk '$2 == "VALIDSIG" {print $3; exit}')"
  test -n "$fingerprint"
  codename="$(grep -m1 '^Codename:' "$f" | cut -d: -f2- | xargs)"
  test -n "$codename"
  case "$codename" in
__DEBIAN_SIGNATURE_ALLOWLIST__
    *) exit 1 ;;
  esac
  if test "$fingerprint" != "$expected_fingerprint"; then
    printf 'DEBIAN_SIGNATURE_REJECTED suite=%s observed=%s expected=%s\n' \
      "$codename" "$fingerprint" "$expected_fingerprint" >&2
    exit 1
  fi
  file_hash="$(sha256sum "$f" | awk '{print $1}')"
  printf '%s\t%s\t%s\t%s\n' \
    "$(basename "$f")" "$codename" "$fingerprint" "$file_hash" \
    >> /audit/inrelease.tsv
done
mark_phase dpkg-dev-install /audit/apt-install.log
apt-get "${apt_opts[@]}" install -y --no-install-recommends dpkg-dev >/audit/apt-install.log 2>&1
sha256sum "$keyring" | awk '{print $1}' > /audit/archive-keyring-after.sha256
cmp /audit/archive-keyring-before.sha256 /audit/archive-keyring-after.sha256
install -d -m 0700 /audit/source
source_tmp="$(mktemp -d /tmp/qemu-source-download.XXXXXX)"
cd "$source_tmp"
mark_phase qemu-source-download /audit/source-download.log
apt-get "${apt_opts[@]}" source --download-only --only-source \
  'qemu=1:7.2+dfsg-7+deb12u18' >/audit/source-download.log 2>&1
dsc=(qemu_7.2+dfsg-7+deb12u18.dsc)
test "${#dsc[@]}" -eq 1
test -f "${dsc[0]}"
test "$(stat -c %s "${dsc[0]}")" -le 1048576
printf '%s  %s\n' '"""
        + QEMU_DSC_SHA256
        + r"""' "${dsc[0]}" | sha256sum --check --status
mv "${dsc[0]}" /audit/source/
mv qemu_7.2+dfsg.orig.tar.xz qemu_7.2+dfsg-7+deb12u18.debian.tar.xz /audit/source/
"""
        + archive_checks
        + r"""
mark_phase qemu-source-extract /audit/source-extract.log
dpkg-source -x /audit/source/qemu_7.2+dfsg-7+deb12u18.dsc /audit/unpacked \
  >/audit/source-extract.log 2>&1
test -f /audit/unpacked/debian/copyright
sha256sum /audit/unpacked/debian/copyright > /audit/debian-copyright.sha256
find /audit/unpacked -maxdepth 1 -type f -name 'COPYING*' -print0 \
  | sort -z \
  | xargs -0 -r sha256sum > /audit/copying-hashes.txt
"""
    ).replace("__DEBIAN_SIGNATURE_ALLOWLIST__", signature_case)
    container_name = f"qemu-source-audit-{uuid.uuid4().hex[:16]}"
    command_args = [
        "docker",
        "create",
        "--name",
        container_name,
        "--network",
        "bridge",
        "--cap-drop=ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "256",
        "--memory",
        "4g",
        "--cpus",
        "2",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=512m,mode=1777",
        "--mount",
        f"type=bind,src={prepared_sources},dst=/etc/apt/sources.list.d/debian.sources,readonly",
        BASE_IMAGE,
        "/bin/bash",
        "-euc",
        command,
    ]
    create_attempted = False
    container_created = False
    try:
        create_attempted = True
        run(command_args, capture=True, timeout=120)
        container_created = True
        try:
            run(["docker", "start", "--attach", container_name], capture=True, timeout=900)
        except (StopBuild, OSError, subprocess.SubprocessError) as exc:
            container_diagnostics = read_container_diagnostics(container_name)
            try:
                copy_audit_files(container_name, audit_dir, AUDIT_LOG_FILES, required=False)
            except (StopBuild, OSError, subprocess.SubprocessError) as copy_exc:
                container_diagnostics.append(
                    "bounded-log-copy-failed: " + str(copy_exc).replace(str(audit_dir), "<audit>")
                )
            diagnostics = read_audit_diagnostics(audit_dir)
            diagnostics.extend(container_diagnostics)
            detail = " | ".join(diagnostics).replace(str(audit_dir), "<audit>")
            raise StopBuild(
                f"{exc}" + (f"; sanitized apt diagnostic: {detail}" if detail else "")
            ) from exc
        copy_audit_files(container_name, audit_dir, AUDIT_EVIDENCE_FILES, required=True)
    finally:
        if create_attempted:
            active_error = sys.exc_info()[1]
            try:
                cleanup = run(
                    ["docker", "rm", "--force", container_name],
                    capture=True,
                    check=False,
                    timeout=60,
                )
                cleanup_failed = cleanup.returncode != 0
            except (OSError, subprocess.SubprocessError):
                cleanup_failed = True
            if cleanup_failed:
                if active_error is None and container_created:
                    raise StopBuild("failed to remove the temporary Debian source audit container")
                if active_error is not None:
                    print(
                        "CLEANUP_WARNING: temporary Debian source audit container "
                        "could not be removed",
                        file=sys.stderr,
                    )


def copy_audit_files(
    container_name: str,
    audit_dir: Path,
    files: tuple[tuple[str, str], ...],
    *,
    required: bool,
) -> None:
    missing = []
    for container_path, relative_path in files:
        target = audit_dir / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        result = run(
            ["docker", "cp", f"{container_name}:{container_path}", str(target)],
            capture=True,
            check=False,
            timeout=120,
        )
        if result.returncode != 0:
            missing.append(relative_path)
            continue
        if target.is_symlink() or not target.is_file():
            raise StopBuild(f"container audit evidence is not a regular file: {relative_path}")
        limit = AUDIT_FILE_MAX_BYTES[relative_path]
        if target.stat().st_size > limit:
            raise StopBuild(f"container audit evidence exceeds its size limit: {relative_path}")
    if required and missing:
        raise StopBuild("container did not produce required audit evidence: " + ", ".join(missing))


def read_audit_diagnostics(audit_dir: Path) -> list[str]:
    diagnostics = []
    failure_pattern = re.compile(
        r"(?i)\b(?:error|fatal|failed|failure|unable|cannot|denied|not permitted|chown)\b"
        r"|(?:^|\s)[EW]:"
    )
    for _, name in AUDIT_LOG_FILES:
        path = audit_dir / name
        if path.is_file() and not path.is_symlink():
            with path.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                stream.seek(max(0, stream.tell() - AUDIT_FILE_MAX_BYTES[name]))
                lines = (
                    stream.read(AUDIT_FILE_MAX_BYTES[name])
                    .decode("utf-8", errors="replace")
                    .splitlines()
                )
            failures = [line for line in lines if failure_pattern.search(line)]
            selected = list(dict.fromkeys([*failures[-16:], *lines[-8:]]))[-24:]
            for line in selected:
                sanitized = re.sub(r"(?i)(https?://)[^/\s@]+@", r"\1[redacted]@", line)
                sanitized = re.sub(r"[\x00-\x1f\x7f]+", " ", sanitized)
                sanitized = sanitized.replace(str(ROOT), "<workspace>")
                if not sanitized.startswith("FIRMWARE_FREE_"):
                    diagnostics.append(f"{name}: {sanitized[:500]}")
    return diagnostics[-24:]


def read_container_diagnostics(container_name: str) -> list[str]:
    try:
        result = run(
            ["docker", "logs", container_name],
            capture=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    lines = []
    for line in (result.stdout or "").splitlines()[-12:]:
        sanitized = re.sub(r"(?i)(https?://)[^/\s@]+@", r"\1[redacted]@", line)
        sanitized = re.sub(r"[\x00-\x1f\x7f]+", " ", sanitized)
        sanitized = sanitized.replace(str(ROOT), "<workspace>")
        lines.append(sanitized[:500])
    return lines


def debian_license_inventory(copyright_text: str) -> dict[str, Any]:
    lines = copyright_text.splitlines()
    expressions: set[str] = set()
    full_text_hashes: set[str] = set()
    empty_entries = 0
    license_field_count = 0
    for index, line in enumerate(lines):
        if not line.startswith("License:"):
            continue
        license_field_count += 1
        value = line.partition(":")[2].strip()
        if value:
            expressions.add(value.split()[0][:160])
            continue
        continuation = []
        for following in lines[index + 1 :]:
            if not following.strip():
                break
            if not following.startswith((" ", "\t")):
                break
            continuation.append(following[1:])
        if continuation:
            text = "\n".join(continuation).encode("utf-8")
            full_text_hashes.add(hashlib.sha256(text).hexdigest())
        else:
            empty_entries += 1
    return {
        "license_field_count": license_field_count,
        "license_expressions": sorted(expressions),
        "full_text_license_block_count": len(full_text_hashes),
        "full_text_license_block_sha256": sorted(full_text_hashes),
        "empty_license_field_count": empty_entries,
    }


def verify_source_audit(audit_dir: Path) -> dict[str, Any]:
    files = {path.name: path for path in (audit_dir / "source").iterdir() if path.is_file()}
    dscs = [path for path in files.values() if path.suffix == ".dsc"]
    if len(dscs) != 1 or digest(dscs[0]) != QEMU_DSC_SHA256:
        raise StopBuild("QEMU source descriptor did not match the reviewed M1-01 SHA-256")
    dsc_text = dscs[0].read_text(encoding="utf-8", errors="strict")
    if f"Version: {QEMU_VERSION}" not in dsc_text or not re.search(
        r"(?m)^Source: qemu\s*$", dsc_text
    ):
        raise StopBuild("QEMU source descriptor identity differs from the reviewed source version")
    checksum_section = re.search(r"(?m)^Checksums-Sha256:\s*\n((?:[ \t].*\n)+)", dsc_text)
    if not checksum_section:
        raise StopBuild("QEMU source descriptor has no SHA-256 archive table")
    declared = {}
    for row in checksum_section.group(1).splitlines():
        parts = row.split()
        if len(parts) == 3:
            declared[parts[2]] = (int(parts[1]), parts[0])
    archive_report = {}
    for name, (expected_bytes, expected_hash) in QEMU_ARCHIVES.items():
        path = files.get(name)
        if path is None or path.stat().st_size != expected_bytes or digest(path) != expected_hash:
            raise StopBuild(f"QEMU source archive checksum or size mismatch: {name}")
        if declared.get(name) != (expected_bytes, expected_hash):
            raise StopBuild(f"QEMU source descriptor checksum table mismatch: {name}")
        archive_report[name] = {"bytes": expected_bytes, "sha256": expected_hash, "verified": True}

    signatures = []
    for line in (audit_dir / "inrelease.tsv").read_text(encoding="utf-8").splitlines():
        name, codename, fingerprint, sha256 = line.split("\t")
        signatures.append(
            {
                "file": name,
                "codename": codename,
                "valid_signature_fingerprint": fingerprint,
                "sha256": sha256,
                "verified": True,
            }
        )
    if {item["codename"] for item in signatures} != {
        "bookworm",
        "bookworm-updates",
        "bookworm-security",
    }:
        raise StopBuild("the three expected Debian snapshot InRelease suites were not all verified")
    copyright_path = audit_dir / "unpacked" / "debian" / "copyright"
    copyright_text = copyright_path.read_text(encoding="utf-8", errors="replace")
    license_inventory = debian_license_inventory(copyright_text)
    return {
        "debian_snapshot_inrelease": signatures,
        "debian_archive_keyring_sha256": (audit_dir / "archive-keyring-before.sha256")
        .read_text(encoding="ascii")
        .strip(),
        "qemu_dsc_sha256": QEMU_DSC_SHA256,
        "qemu_dsc_openpgp_signature": (
            "not independently checked; descriptor hash is authenticated by the "
            "signed Debian Sources index"
        ),
        "source_archives": archive_report,
        "source_extraction": (
            "dpkg-source extraction only; no upstream configure, build, or "
            "maintainer script executed"
        ),
        "debian_copyright_sha256": digest(copyright_path),
        "debian_copyright_license_inventory": license_inventory,
        "top_level_copying_file_hashes": [
            line.strip()
            for line in (audit_dir / "copying-hashes.txt").read_text(encoding="utf-8").splitlines()
        ],
    }


def prepare_build_inputs(
    upstream: Path,
    audit_dir: Path,
    destination: Path,
    source_hashes: dict[str, str],
) -> str:
    source_paths = {
        "LICENSE": upstream / "LICENSE",
        "emulator/docker/Dockerfile": upstream / "emulator/docker/Dockerfile",
        "emulator/docker/debian.sources": upstream / "emulator/docker/debian.sources",
        "emulator/docker/qemu/snowsky-disc-devices.patch": (
            upstream / "emulator/docker/qemu/snowsky-disc-devices.patch"
        ),
        **{
            f"emulator/shims/{name}": upstream / "emulator/shims" / name
            for name in (
                "asndshim.c",
                "asound.cards",
                "build_shims.sh",
                "capture.h",
                "fbshim.c",
                "mqshim.c",
                "tinyshim.c",
            )
        },
    }
    destination.mkdir(parents=True, exist_ok=True)
    expected_hashes: dict[str, str] = {}
    for relative, source in source_paths.items():
        expected = REVIEWED_SOURCE_IDENTITIES[relative][1]
        if source_hashes.get(relative) != expected or source.is_symlink() or not source.is_file():
            raise StopBuild(f"reviewed build input is missing or changed: {relative}")
        target = destination / "upstream" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if digest(target) != expected:
            raise StopBuild(f"copied build input did not retain its reviewed identity: {relative}")
        expected_hashes[f"upstream/{relative}"] = expected

    source_dir = destination / "qemu"
    source_dir.mkdir(exist_ok=True)
    source_files = {
        "qemu_7.2+dfsg-7+deb12u18.dsc": (QEMU_DSC_SHA256, 1024 * 1024),
        **{name: (sha256, size) for name, (size, sha256) in QEMU_ARCHIVES.items()},
    }
    for name, (expected, max_bytes) in source_files.items():
        source = audit_dir / "source" / name
        if source.is_symlink() or not source.is_file() or source.stat().st_size > max_bytes:
            raise StopBuild(f"verified QEMU source input is missing or oversized: {name}")
        if digest(source) != expected:
            raise StopBuild(f"verified QEMU source input changed before the build: {name}")
        shutil.copyfile(source, source_dir / name)
        expected_hashes[f"qemu/{name}"] = expected

    helper = ROOT / "scripts" / "ci" / "qemu_runtime_build.py"
    if helper.is_symlink() or not helper.is_file():
        raise StopBuild("Lab build evidence helper is missing or unsafe")
    helper_target = destination / "lab" / "qemu_runtime_build.py"
    helper_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(helper, helper_target)
    helper_hash = digest(helper)
    if digest(helper_target) != helper_hash:
        raise StopBuild("Lab build evidence helper changed while preparing the build")
    expected_hashes["lab/qemu_runtime_build.py"] = helper_hash

    lines = [f"{value}  {name}" for name, value in sorted(expected_hashes.items())]
    manifest = destination / "SHA256SUMS"
    manifest.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    return digest(manifest)


def build_container_args(inputs_dir: Path, command: str, container_name: str) -> list[str]:
    return [
        "docker",
        "create",
        "--name",
        container_name,
        "--network",
        "bridge",
        "--cap-drop=ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "256",
        "--memory",
        "6g",
        "--cpus",
        "2",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=512m,mode=1777",
        "--tmpfs",
        "/build:rw,nosuid,nodev,size=6g,mode=0755",
        "--mount",
        f"type=bind,src={inputs_dir.resolve()},dst=/inputs,readonly",
        BASE_IMAGE,
        "/bin/bash",
        "-euc",
        command,
    ]


def build_container_command(reference: dict[str, Any]) -> str:
    inputs = reference["buildInputs"]
    native_packages = tuple(inputs["nativeBuildPackageRequests"])
    cross_packages = tuple(inputs["shimToolchain"]["packages"])
    configure_flags = tuple(inputs["qemu"]["configureFlags"])
    if native_packages != NATIVE_BUILD_PACKAGES or cross_packages != CROSS_SHIM_PACKAGES:
        raise StopBuild("build package set differs from the reviewed M1-01 manifest")
    if configure_flags != QEMU_CONFIGURE_FLAGS:
        raise StopBuild("QEMU configure flags differ from the reviewed M1-01 manifest")

    package_args = " ".join(shlex.quote(item) for item in (*native_packages, *cross_packages))
    configure_args = " ".join(shlex.quote(item) for item in configure_flags)
    archive_checks = "\n".join(
        f"printf '%s  %s\\n' '{sha256}' '/inputs/qemu/{name}' | sha256sum --check --status"
        for name, (_, sha256) in QEMU_ARCHIVES.items()
    )
    signature_case = "\n".join(
        f"    {suite}) expected_fingerprint='{fingerprint}' ;;"
        for suite, fingerprint in DEBIAN_SIGNING_FINGERPRINTS.items()
    )
    script = r"""set -eEuo pipefail
exec 3>&2
phase=container-initialization
failure_log=
report_failure() {
  failure_status=$?
  trap - ERR
  printf 'FIRMWARE_FREE_PHASE_FAILURE phase=%s exit=%s\n' "$phase" "$failure_status" >&3
  if [[ -n "$failure_log" && -f "$failure_log" ]]; then
    printf '%s\n' 'FIRMWARE_FREE_LOG_TAIL_BEGIN' >&3
    tail -n 12 "$failure_log" | sed -E 's/[[:cntrl:]]/ /g' | cut -c1-500 >&3
    printf '%s\n' 'FIRMWARE_FREE_LOG_TAIL_END' >&3
  fi
  exit "$failure_status"
}
trap report_failure ERR
install -d -m 0700 /audit
mark_phase() {
  phase="$1"
  failure_log="$2"
  printf '%s\n' "$phase" > /audit/phase
  printf '%s\n' "$failure_log" > /audit/failure-log
}
mark_phase container-initialization ""
install -d -m 0755 /etc/apt/sources.list.d
cp /inputs/upstream/emulator/docker/debian.sources /etc/apt/sources.list.d/debian.sources
test ! -e /etc/apt/sources.list
test -f /etc/apt/sources.list.d/debian.sources
test "$(find /etc/apt/sources.list.d -maxdepth 1 -type f | wc -l)" -eq 1
cd /inputs
mark_phase reviewed-input-integrity /audit/input-hash-check.log
sha256sum --check /inputs/SHA256SUMS >/audit/input-hash-check.log 2>&1
export DEBIAN_FRONTEND=noninteractive
apt_opts=(
  -o APT::Sandbox::User=root
  -o Dpkg::Use-Pty=false
  -o Dir::Log=/dev/null
  -o Dir::Etc::sourcelist=/dev/null
  -o Dir::Etc::sourceparts=/etc/apt/sources.list.d
  -o Acquire::Languages=none
  -o Acquire::AllowInsecureRepositories=false
  -o Acquire::AllowDowngradeToInsecureRepositories=false
  -o Acquire::AllowWeakRepositories=false
  -o APT::Get::AllowUnauthenticated=false
)
apt() {
  apt-get "${apt_opts[@]}" "$@"
}
mark_phase debian-index-update /audit/apt-update.log
apt update >/audit/apt-update.log 2>&1
keyring=/usr/share/keyrings/debian-archive-keyring.gpg
sha256sum "$keyring" | awk '{print $1}' > /audit/archive-keyring-before.sha256
: > /audit/inrelease.tsv
mark_phase debian-signature-verification /audit/apt-update.log
for f in /var/lib/apt/lists/*_InRelease; do
  status="$(gpgv --status-fd 1 --keyring "$keyring" "$f" 2>&1)"
  fingerprint="$(printf '%s\n' "$status" | awk '$2 == "VALIDSIG" {print $3; exit}')"
  test -n "$fingerprint"
  codename="$(grep -m1 '^Codename:' "$f" | cut -d: -f2- | xargs)"
  test -n "$codename"
  case "$codename" in
__DEBIAN_SIGNATURE_ALLOWLIST__
    *) exit 1 ;;
  esac
  if test "$fingerprint" != "$expected_fingerprint"; then
    printf 'DEBIAN_SIGNATURE_REJECTED suite=%s observed=%s expected=%s\n' \
      "$codename" "$fingerprint" "$expected_fingerprint" >&2
    exit 1
  fi
  file_hash="$(sha256sum "$f" | awk '{print $1}')"
  printf '%s\t%s\t%s\t%s\n' "$(basename "$f")" "$codename" "$fingerprint" "$file_hash" \
    >> /audit/inrelease.tsv
done
for suite in bookworm bookworm-updates bookworm-security; do
  grep -q "$(printf '\t%s\t' "$suite")" /audit/inrelease.tsv
done
mark_phase fakeroot-bootstrap /audit/apt-install.log
: > /audit/apt-install.log
fakeroot_deb_dir=/build/fakeroot-debs
fakeroot_root=/build/fakeroot-root
install -d -m 0700 "$fakeroot_deb_dir" "$fakeroot_root"
cd "$fakeroot_deb_dir"
apt download fakeroot-sysv libfakeroot >>/audit/apt-install.log 2>&1
shopt -s nullglob
fakeroot_debs=(fakeroot-sysv_*.deb libfakeroot_*.deb)
test "${#fakeroot_debs[@]}" -eq 2
declare -A fakeroot_seen=()
: > /audit/fakeroot-bootstrap.tsv
for package_file in "${fakeroot_debs[@]}"; do
  test -f "$package_file" && test ! -L "$package_file"
  package_name="$(dpkg-deb -f "$package_file" Package)"
  package_version="$(dpkg-deb -f "$package_file" Version)"
  package_architecture="$(dpkg-deb -f "$package_file" Architecture)"
  package_bytes="$(stat -c %s "$package_file")"
  package_sha256="$(sha256sum "$package_file" | awk '{print $1}')"
  case "$package_name" in
    fakeroot-sysv|libfakeroot) ;;
    *) exit 1 ;;
  esac
  test -z "${fakeroot_seen[$package_name]:-}"
  fakeroot_seen[$package_name]=1
  test "$package_architecture" = amd64
  test -n "$package_version"
  test "$package_bytes" -gt 0 && test "$package_bytes" -le 4194304
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$package_name" "$package_version" "$package_architecture" "$package_bytes" \
    "$package_sha256" >> /audit/fakeroot-bootstrap.tsv
done
test -n "${fakeroot_seen[fakeroot-sysv]:-}"
test -n "${fakeroot_seen[libfakeroot]:-}"
for package_file in "${fakeroot_debs[@]}"; do
  dpkg-deb --fsys-tarfile "$package_file" \
    | tar --no-same-owner -xf - -C "$fakeroot_root"
done
fakeroot_bin="$fakeroot_root/usr/bin/fakeroot-sysv"
fakeroot_daemon="$fakeroot_root/usr/bin/faked-sysv"
fakeroot_library="$fakeroot_root/usr/lib/x86_64-linux-gnu/libfakeroot/libfakeroot-sysv.so"
test -x "$fakeroot_bin" && test -x "$fakeroot_daemon" && test -f "$fakeroot_library"
cd /inputs
mark_phase build-package-install /audit/apt-install.log
"$fakeroot_bin" --lib "$fakeroot_library" --faked "$fakeroot_daemon" -- \
  apt-get "${apt_opts[@]}" install -y --no-install-recommends __BUILD_PACKAGES__ \
  >>/audit/apt-install.log 2>&1
sha256sum "$keyring" | awk '{print $1}' > /audit/archive-keyring-after.sha256
cmp /audit/archive-keyring-before.sha256 /audit/archive-keyring-after.sha256
dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${Architecture}\n' \
  | awk -F '\t' '$1 ~ /^ii/ {print $2 "\t" $3 "\t" $4}' \
  | LC_ALL=C sort > /audit/package-bom.tsv
apt clean
rm -rf /var/lib/apt/lists/*
printf '%s\n' "$(date +%s)" > /audit/build-start-epoch
cd /inputs/qemu
mark_phase qemu-source-integrity ""
test "$(stat -c %s qemu_7.2+dfsg-7+deb12u18.dsc)" -le 1048576
printf '%s  %s\n' '__DSC_SHA256__' qemu_7.2+dfsg-7+deb12u18.dsc \
  | sha256sum --check --status
__ARCHIVE_CHECKS__
mark_phase qemu-source-extract /audit/source-extract.log
dpkg-source -x qemu_7.2+dfsg-7+deb12u18.dsc /build/qemu-7.2+dfsg \
  >/audit/source-extract.log 2>&1
mark_phase qemu-patch-application /audit/patch-application.log
patch --batch --forward --fuzz=0 -p1 --directory=/build/qemu-7.2+dfsg \
  < /inputs/upstream/emulator/docker/qemu/snowsky-disc-devices.patch \
  >/audit/patch-application.log 2>&1
if grep -Eiq 'fuzz|offset|reversed|previously applied|skipping' /audit/patch-application.log; then
  printf '%s\n' 'QEMU patch did not apply cleanly at exact context' >&2
  exit 1
fi
cd /build/qemu-7.2+dfsg
mark_phase qemu-configure /audit/qemu-configure.log
./configure __CONFIGURE_ARGS__ >/audit/qemu-configure.log 2>&1
mark_phase qemu-build /audit/qemu-build.log
ninja -j2 -C build qemu-mipsel >/audit/qemu-build.log 2>&1
mkdir -p /build/shims
mark_phase mips-shim-build /audit/shim-build.log
WORK=/build/shims bash /inputs/upstream/emulator/shims/build_shims.sh \
  >/audit/shim-build.log 2>&1
mark_phase build-evidence-collection ""
python3 /inputs/lab/qemu_runtime_build.py measure
"""
    return (
        script.replace("__BUILD_PACKAGES__", package_args)
        .replace("__DSC_SHA256__", QEMU_DSC_SHA256)
        .replace("__ARCHIVE_CHECKS__", archive_checks)
        .replace("__DEBIAN_SIGNATURE_ALLOWLIST__", signature_case)
        .replace("__CONFIGURE_ARGS__", configure_args)
    )


def validate_build_artifacts(artifacts: Any) -> None:
    if (
        not isinstance(artifacts, list)
        or len(artifacts) != len(EXPECTED_BUILD_ARTIFACTS)
        or any(not isinstance(item, dict) for item in artifacts)
        or {item.get("name") for item in artifacts} != EXPECTED_BUILD_ARTIFACTS
    ):
        raise StopBuild("build artifact set does not contain QEMU and all four reviewed shims")
    for item in artifacts:
        machine = item.get("machine")
        if (
            not isinstance(item.get("name"), str)
            or not isinstance(item.get("bytes"), int)
            or item["bytes"] <= 0
            or not isinstance(item.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
            or item.get("has_interpreter") is not False
            or not isinstance(machine, str)
        ):
            raise StopBuild("build artifact identity or static ELF report is invalid")
        if item["name"] == "qemu-mipsel":
            if (
                item.get("elf_class") != "ELF64"
                or item.get("elf_data") != "little endian"
                or "x86-64" not in machine.lower()
            ):
                raise StopBuild("QEMU artifact is not the expected static Linux x86_64 executable")
        elif (
            item.get("elf_class") != "ELF32"
            or item.get("elf_data") != "little endian"
            or "mips" not in machine.lower()
            or item.get("flags") != "0x70001407"
        ):
            raise StopBuild("shim ABI or NaN2008 ELF flags differ from the reviewed MIPS profile")


def read_fakeroot_bootstrap_evidence(path: Path) -> list[dict[str, Any]]:
    packages = []
    names = set()
    try:
        rows = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise StopBuild("fakeroot bootstrap package evidence is missing or invalid") from exc
    for row in rows:
        fields = row.split("\t")
        if len(fields) != 5:
            raise StopBuild("fakeroot bootstrap package evidence is malformed")
        name, version, architecture, byte_text, sha256 = fields
        try:
            size = int(byte_text)
        except ValueError as exc:
            raise StopBuild("fakeroot bootstrap package size is malformed") from exc
        if (
            name not in FAKEROOT_BOOTSTRAP_PACKAGES
            or name in names
            or not version
            or len(version) > 128
            or architecture != "amd64"
            or not 0 < size <= 4 * 1024 * 1024
            or not re.fullmatch(r"[0-9a-f]{64}", sha256)
        ):
            raise StopBuild("fakeroot bootstrap package identity is invalid")
        names.add(name)
        packages.append(
            {
                "package": name,
                "version": version,
                "architecture": architecture,
                "bytes": size,
                "sha256": sha256,
            }
        )
    if names != set(FAKEROOT_BOOTSTRAP_PACKAGES):
        raise StopBuild("fakeroot bootstrap package set is incomplete")
    return sorted(packages, key=lambda item: item["package"])


def run_build_container(
    inputs_dir: Path,
    report_path: Path,
    reference: dict[str, Any],
    *,
    timeout_seconds: int = 2100,
) -> dict[str, Any]:
    command = build_container_command(reference)
    container_name = f"qemu-runtime-build-{uuid.uuid4().hex[:16]}"
    create_attempted = False
    container_created = False
    try:
        create_attempted = True
        run(build_container_args(inputs_dir, command, container_name), capture=True, timeout=120)
        container_created = True
        try:
            run(
                ["docker", "start", "--attach", container_name],
                capture=True,
                timeout=timeout_seconds,
            )
        except (StopBuild, OSError, subprocess.SubprocessError) as exc:
            diagnostic_dir = report_path.parent / "failed-container-diagnostics"
            diagnostics = []
            try:
                copy_audit_files(container_name, diagnostic_dir, AUDIT_LOG_FILES, required=False)
                diagnostics.extend(read_audit_diagnostics(diagnostic_dir))
            except (StopBuild, OSError, subprocess.SubprocessError) as copy_exc:
                diagnostics.append("bounded-log-copy-failed: " + str(copy_exc))
            diagnostics.extend(read_container_diagnostics(container_name))
            detail = " | ".join(diagnostics)
            if detail:
                raise StopBuild(f"{exc}; bounded container diagnostic: {detail}") from exc
            raise
        copy_audit_files(container_name, report_path.parent, BUILD_EVIDENCE_FILES, required=True)
        if report_path.is_symlink() or not report_path.is_file():
            raise StopBuild("build evidence receipt is not a regular file")
        try:
            evidence = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StopBuild("build evidence receipt is malformed") from exc
        if not isinstance(evidence, dict) or evidence.get("schema_version") != (
            "firmware-free-qemu-runtime-build/v1"
        ):
            raise StopBuild("build evidence receipt has an unsupported schema")
        if evidence.get("status") != "build-passed-binaries-ephemeral":
            raise StopBuild("build evidence receipt does not record a successful build")
        validate_build_artifacts(evidence.get("artifacts"))
        if evidence.get("retention", {}).get("compiled_binaries_published") is not False:
            raise StopBuild(
                "build evidence does not confirm that compiled binaries were not published"
            )
        return evidence
    finally:
        if create_attempted:
            active_error = sys.exc_info()[1]
            try:
                cleanup = run(
                    ["docker", "rm", "--force", container_name],
                    capture=True,
                    check=False,
                    timeout=60,
                )
                cleanup_failed = cleanup.returncode != 0
            except (OSError, subprocess.SubprocessError):
                cleanup_failed = True
            if cleanup_failed:
                if active_error is None and container_created:
                    raise StopBuild("failed to remove the temporary QEMU build container")
                if active_error is not None:
                    print(
                        "CLEANUP_WARNING: temporary QEMU build container could not be removed",
                        file=sys.stderr,
                    )


def _tool_output(args: list[str]) -> str:
    result = subprocess.run(
        args,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    if result.returncode:
        raise StopBuild(f"build evidence command failed: {args[0]}")
    return result.stdout.strip()


def _tree_digest(root: Path) -> tuple[str, int, int]:
    if root.is_symlink() or not root.is_dir():
        raise StopBuild("cross toolchain sysroot directory is missing")
    entries = sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())
    if len(entries) > 100_000:
        raise StopBuild("cross toolchain sysroot exceeds the 100000-entry evidence limit")
    value = hashlib.sha256()
    file_count = 0
    for path in entries:
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            record = f"L\t{relative}\t{os.readlink(path)}\n".encode()
        elif path.is_file():
            record = f"F\t{relative}\t{path.stat().st_size}\t{digest(path)}\n".encode()
            file_count += 1
        elif path.is_dir():
            record = f"D\t{relative}\n".encode()
        else:
            raise StopBuild("cross toolchain sysroot contains a special file")
        value.update(record)
    return value.hexdigest(), file_count, len(entries)


def _elf_evidence(name: str, path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise StopBuild(f"expected regular build output is missing: {name}")
    max_bytes = 150 * 1024 * 1024 if name == "qemu-mipsel" else 16 * 1024 * 1024
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise StopBuild(f"build output is outside its documented size bound: {name}")
    header = _tool_output(["readelf", "-h", str(path)])
    program_headers = _tool_output(["readelf", "-l", str(path)])
    fields: dict[str, str] = {}
    for line in header.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key.strip()] = value.strip()
    flags_match = re.match(r"(0x[0-9a-fA-F]+)", fields.get("Flags", ""))
    data = fields.get("Data", "").lower()
    return {
        "name": name,
        "bytes": size,
        "sha256": digest(path),
        "elf_class": fields.get("Class", ""),
        "elf_data": "little endian" if "little endian" in data else data,
        "machine": fields.get("Machine", ""),
        "flags": flags_match.group(1).lower() if flags_match else "",
        "has_interpreter": bool(re.search(r"(?m)^\s*INTERP\s", program_headers)),
    }


def measure_build_evidence() -> None:
    package_bom = Path("/audit/package-bom.tsv")
    package_raw = package_bom.read_bytes()
    packages = []
    for row in package_raw.decode("utf-8", errors="strict").splitlines():
        fields = row.split("\t")
        if len(fields) != 3:
            raise StopBuild("installed package BOM is malformed")
        packages.append({"package": fields[0], "version": fields[1], "architecture": fields[2]})
    if not packages:
        raise StopBuild("installed package BOM is empty")
    fakeroot_bootstrap_packages = read_fakeroot_bootstrap_evidence(
        Path("/audit/fakeroot-bootstrap.tsv")
    )

    sysroot = Path("/usr/mipsel-linux-gnu")
    sysroot_sha256, sysroot_file_count, sysroot_entry_count = _tree_digest(sysroot)
    tool_names = (
        "gcc",
        "ld",
        "ninja",
        "meson",
        "mipsel-linux-gnu-gcc",
        "mipsel-linux-gnu-ld",
        "mipsel-linux-gnu-readelf",
    )
    executable_evidence = {}
    for name in tool_names:
        located = shutil.which(name)
        if located is None:
            raise StopBuild(f"reviewed build tool is missing: {name}")
        resolved = Path(located).resolve(strict=True)
        executable_evidence[name] = {
            "path": str(Path(located).as_posix()),
            "sha256": digest(resolved),
        }

    artifacts = [
        _elf_evidence("qemu-mipsel", Path("/build/qemu-7.2+dfsg/build/qemu-mipsel")),
        _elf_evidence("fbshim.so", Path("/build/shims/fbshim.so")),
        _elf_evidence("asndshim.so", Path("/build/shims/asndshim.so")),
        _elf_evidence("tinyshim.so", Path("/build/shims/tinyshim.so")),
        _elf_evidence("mqshim.so", Path("/build/shims/mqshim.so")),
    ]
    validate_build_artifacts(artifacts)

    signatures = []
    for row in Path("/audit/inrelease.tsv").read_text(encoding="utf-8").splitlines():
        fields = row.split("\t")
        if len(fields) != 4:
            raise StopBuild("signed Debian snapshot evidence is malformed")
        name, codename, fingerprint, file_hash = fields
        signatures.append(
            {
                "file": name,
                "codename": codename,
                "valid_signature_fingerprint": fingerprint,
                "sha256": file_hash,
                "verified": True,
            }
        )
    expected_suites = {"bookworm", "bookworm-updates", "bookworm-security"}
    if {item["codename"] for item in signatures} != expected_suites:
        raise StopBuild("the three expected Debian signed snapshot suites are not present")

    build_logs = {}
    for label, name in (
        ("apt_update", "apt-update.log"),
        ("apt_install", "apt-install.log"),
        ("source_hash_check", "input-hash-check.log"),
        ("source_extract", "source-extract.log"),
        ("patch_application", "patch-application.log"),
        ("qemu_configure", "qemu-configure.log"),
        ("qemu_build", "qemu-build.log"),
        ("shim_build", "shim-build.log"),
    ):
        path = Path("/audit") / name
        if path.is_symlink() or not path.is_file():
            raise StopBuild(f"bounded build log is missing: {name}")
        build_logs[label] = {"bytes": path.stat().st_size, "sha256": digest(path)}

    cross_packages = [
        item for item in packages if item["package"].split(":", 1)[0] in CROSS_SHIM_PACKAGES
    ]
    if {item["package"].split(":", 1)[0] for item in cross_packages} != set(CROSS_SHIM_PACKAGES):
        raise StopBuild("the three reviewed shim toolchain packages are not installed")

    started = int(Path("/audit/build-start-epoch").read_text(encoding="ascii").strip())
    evidence = {
        "schema_version": "firmware-free-qemu-runtime-build/v1",
        "status": "build-passed-binaries-ephemeral",
        "artifacts": artifacts,
        "debian_snapshot_inrelease": signatures,
        "debian_archive_keyring_sha256": Path("/audit/archive-keyring-before.sha256")
        .read_text(encoding="ascii")
        .strip(),
        "package_bom_sha256": hashlib.sha256(package_raw).hexdigest(),
        "package_count": len(packages),
        "installed_packages": packages,
        "fakeroot_bootstrap_packages": fakeroot_bootstrap_packages,
        "toolchain": {
            "native": {
                "gcc_version": _tool_output(["gcc", "-dumpfullversion", "-dumpversion"]),
                "binutils_version": _tool_output(["ld", "--version"]).splitlines()[0],
                "meson_version": _tool_output(["meson", "--version"]).splitlines()[0],
                "ninja_version": _tool_output(["ninja", "--version"]).splitlines()[0],
                "python_version": _tool_output(["python3", "--version"]).splitlines()[0],
            },
            "mipsel": {
                "compiler": "mipsel-linux-gnu-gcc",
                "compiler_version": _tool_output(
                    ["mipsel-linux-gnu-gcc", "--version"]
                ).splitlines()[0],
                "version": _tool_output(
                    ["mipsel-linux-gnu-gcc", "-dumpfullversion", "-dumpversion"]
                ),
                "target": _tool_output(["mipsel-linux-gnu-gcc", "-dumpmachine"]),
                "reported_sysroot": _tool_output(["mipsel-linux-gnu-gcc", "-print-sysroot"]),
                "sysroot_tree": "/usr/mipsel-linux-gnu",
                "sysroot_sha256": sysroot_sha256,
                "sysroot_file_count": sysroot_file_count,
                "sysroot_entry_count": sysroot_entry_count,
                "compiler_packages": cross_packages,
            },
            "executable_sha256": executable_evidence,
        },
        "build_logs": build_logs,
        "input_manifest_sha256": digest(Path("/inputs/SHA256SUMS")),
        "configure_flags": list(QEMU_CONFIGURE_FLAGS),
        "elapsed_seconds": max(0, int(time.time()) - started),
        "limits": {
            "container_memory_bytes": 6 * 1024**3,
            "container_cpus": 2,
            "build_tmpfs_bytes": 6 * 1024**3,
            "temporary_storage_bytes": 512 * 1024**2,
            "input_mount": "read-only",
            "capabilities": "all dropped",
            "no_new_privileges": True,
            "network_mode": "bridge; runner egress is not isolated at network level",
        },
        "retention": {
            "copied_out": ["sanitized JSON build evidence only"],
            "compiled_binaries_published": False,
            "container_image_built_or_published": False,
        },
    }
    validate_build_artifacts(evidence["artifacts"])
    report_path = Path("/audit/build-evidence.json")
    if report_path.exists() or report_path.is_symlink():
        raise StopBuild("build evidence path already exists")
    report_path.write_text(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def write_summary(title: str, receipt: dict[str, Any]) -> None:
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    print(f"QEMU_RUNTIME_RECEIPT_JSON={encoded}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write(
                f"## {title}\n\n```json\n{json.dumps(receipt, indent=2, sort_keys=True)}\n```\n"
            )


def preflight() -> None:
    started = time.monotonic()
    reference = read_reference()
    resources = resource_report()
    if resources["capacity_status"] != "sufficient":
        receipt = {
            "schema_version": "firmware-free-qemu-runtime-preflight/v1",
            "status": "stopped-insufficient-runner-resources",
            "host_resources": resources,
            "build": "not run; runner capacity did not meet the documented estimate",
        }
        write_summary("Firmware-free QEMU build stopped before image pull", receipt)
        raise StopBuild("runner resources are below the documented build estimate")
    with tempfile.TemporaryDirectory(prefix="qemu-runtime-preflight-") as temporary:
        workdir = Path(temporary)
        upstream, source_hashes, source_sizes = fetch_reviewed_upstream(workdir, reference)
        base = verify_base_image()
        audit = workdir / "debian-audit"
        source_audit_container(upstream / "emulator" / "docker" / "debian.sources", audit)
        debian = verify_source_audit(audit)
    receipt = {
        "schema_version": "firmware-free-qemu-runtime-preflight/v1",
        "status": "preflight-passed-build-not-run",
        "host_resources": resources,
        "upstream": {
            "repository": UPSTREAM,
            "commit": UPSTREAM_COMMIT,
            "selected_paths": ["LICENSE", "emulator/docker/", "emulator/shims/"],
            "firmware_tree_fetched": False,
            "reviewed_file_sha256": source_hashes,
            "reviewed_file_bytes": source_sizes,
        },
        "base_image": base,
        "qemu_source_review": debian,
        "network_boundary": (
            "GitHub, the pinned Debian snapshot in the reviewed debian.sources file, "
            "and the exact pinned container image registry reference were used. "
            "GitHub-hosted runner networking is not network-level egress isolation."
        ),
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "build": "not run; preflight and license evidence review precede compilation",
    }
    write_summary("Firmware-free QEMU build preflight", receipt)


def verify_license_evidence(
    upstream: Path, source_hashes: dict[str, str], qemu_source_review: dict[str, Any]
) -> dict[str, Any]:
    license_path = upstream / "LICENSE"
    expected_hash = REVIEWED_SOURCE_IDENTITIES["LICENSE"][1]
    if (
        source_hashes.get("LICENSE") != expected_hash
        or license_path.is_symlink()
        or not license_path.is_file()
        or digest(license_path) != expected_hash
    ):
        raise StopBuild("pinned upstream license evidence did not match its reviewed identity")
    license_text = license_path.read_text(encoding="utf-8", errors="strict")
    if license_text.splitlines()[0] != "MIT License":
        raise StopBuild("pinned upstream LICENSE declaration changed")
    debian_copyright_hash = qemu_source_review.get("debian_copyright_sha256")
    license_inventory = qemu_source_review.get("debian_copyright_license_inventory", {})
    if not isinstance(debian_copyright_hash, str) or not re.fullmatch(
        r"[0-9a-f]{64}", debian_copyright_hash
    ):
        raise StopBuild("Debian QEMU copyright evidence is missing")
    if (
        not isinstance(license_inventory, dict)
        or license_inventory.get("license_field_count", 0) <= 0
    ):
        raise StopBuild("Debian QEMU copyright file did not yield a license inventory")
    return {
        "status": "evidence-collected-review-required",
        "upstream_repository_license": {
            "declared": "MIT",
            "sha256": expected_hash,
            "scope": "pinned upstream repository LICENSE only",
        },
        "debian_qemu_copyright": {
            "sha256": debian_copyright_hash,
            "inventory": license_inventory,
        },
        "distribution_clearance": False,
        "note": (
            "QEMU source, Debian packaging, patch, and transitive build dependency "
            "provenance has not received a redistribution clearance decision. "
            "This build is ephemeral and outputs are not published."
        ),
    }


def _artifact_hashes(evidence: dict[str, Any]) -> dict[str, str]:
    return {item["name"]: item["sha256"] for item in evidence["artifacts"]}


def compare_clean_builds(first: dict[str, Any], second: dict[str, Any]) -> dict[str, Any]:
    differences = []
    first_artifacts = _artifact_hashes(first)
    second_artifacts = _artifact_hashes(second)
    for name in sorted(EXPECTED_BUILD_ARTIFACTS):
        if first_artifacts.get(name) != second_artifacts.get(name):
            differences.append(f"artifact:{name}")
    if first.get("package_bom_sha256") != second.get("package_bom_sha256"):
        differences.append("installed-package-bom")
    first_toolchain = first.get("toolchain", {})
    second_toolchain = second.get("toolchain", {})
    if first_toolchain.get("mipsel", {}).get("sysroot_sha256") != second_toolchain.get(
        "mipsel", {}
    ).get("sysroot_sha256"):
        differences.append("mipsel-sysroot")
    if first_toolchain.get("executable_sha256") != second_toolchain.get("executable_sha256"):
        differences.append("tool-executables")
    if first.get("input_manifest_sha256") != second.get("input_manifest_sha256"):
        differences.append("source-input-manifest")
    return {
        "status": "identical" if not differences else "different",
        "compared": [
            "QEMU and four shim SHA-256 values",
            "installed package BOM SHA-256",
            "MIPS sysroot SHA-256",
            "tool executable SHA-256 values",
            "reviewed input manifest SHA-256",
        ],
        "differences": differences,
        "second_artifact_sha256": second_artifacts,
        "second_package_bom_sha256": second.get("package_bom_sha256"),
        "second_sysroot_sha256": second_toolchain.get("mipsel", {}).get("sysroot_sha256"),
    }


def build_status_for_repeat(repeat_status: str) -> str:
    suffix = {
        "identical": "identical",
        "different": "different",
        "attempted-failed": "failed",
    }.get(repeat_status, "not-run")
    return f"firmware-free-build-passed-repeat-{suffix}"


def build() -> None:
    started = time.monotonic()
    reference = read_reference()
    resources = resource_report()
    if resources["capacity_status"] != "sufficient":
        receipt = {
            "schema_version": "firmware-free-qemu-runtime-build/v1",
            "status": "stopped-insufficient-runner-resources",
            "host_resources": resources,
            "build": "not run; runner capacity did not meet the documented estimate",
        }
        write_summary("Firmware-free QEMU build stopped before image pull", receipt)
        raise StopBuild("runner resources are below the documented build estimate")

    with tempfile.TemporaryDirectory(prefix="qemu-runtime-build-") as temporary:
        workdir = Path(temporary)
        upstream, source_hashes, source_sizes = fetch_reviewed_upstream(workdir, reference)
        base = verify_base_image()
        audit = workdir / "debian-audit"
        source_audit_container(upstream / "emulator" / "docker" / "debian.sources", audit)
        debian = verify_source_audit(audit)
        license_report = verify_license_evidence(upstream, source_hashes, debian)
        inputs_dir = workdir / "build-inputs"
        input_manifest_sha256 = prepare_build_inputs(upstream, audit, inputs_dir, source_hashes)
        build_started = time.monotonic()
        first = run_build_container(inputs_dir, workdir / "build-evidence.json", reference)
        first_elapsed = round(time.monotonic() - build_started, 1)
        if first.get("debian_archive_keyring_sha256") != debian.get(
            "debian_archive_keyring_sha256"
        ):
            raise StopBuild("Debian archive keyring identity changed between preflight and build")

        repeat: dict[str, Any] = {
            "status": "not-run",
            "reason": (
                "second clean build requires sufficient measured resources and remaining "
                "45-minute job budget"
            ),
        }
        second_resource_report: dict[str, Any] | None = None
        try:
            second_resource_report = resource_report()
        except (StopBuild, OSError, subprocess.SubprocessError) as exc:
            repeat["reason"] = "resource recheck failed after first build: " + str(exc)[:300]
        job_budget_seconds = 42 * 60
        reserve_seconds = 120
        estimate_seconds = max(5 * 60, int(first_elapsed * 1.25))
        available_seconds = int(job_budget_seconds - (time.monotonic() - started) - reserve_seconds)
        if (
            second_resource_report is not None
            and second_resource_report["capacity_status"] == "sufficient"
            and available_seconds >= estimate_seconds
        ):
            second_started = time.monotonic()
            second_path = workdir / "second" / "build-evidence.json"
            try:
                second = run_build_container(
                    inputs_dir,
                    second_path,
                    reference,
                    timeout_seconds=min(estimate_seconds, available_seconds),
                )
                repeat = compare_clean_builds(first, second)
                repeat["elapsed_seconds"] = round(time.monotonic() - second_started, 1)
                repeat["resource_recheck"] = second_resource_report
            except (StopBuild, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
                repeat = {
                    "status": "attempted-failed",
                    "reason": str(exc).replace(str(workdir), "<build>")[:500],
                    "elapsed_seconds": round(time.monotonic() - second_started, 1),
                    "resource_recheck": second_resource_report,
                }
        elif second_resource_report is not None:
            repeat["resource_recheck"] = second_resource_report
            if second_resource_report["capacity_status"] != "sufficient":
                repeat["reason"] = (
                    "runner resources fell below the documented gate after the first build"
                )
            else:
                repeat["reason"] = (
                    "insufficient time remained for a bounded clean rebuild and 2-minute cleanup "
                    "reserve within the 45-minute job"
                )

        repeat_status = repeat.get("status", "not-run")
        receipt_status = build_status_for_repeat(repeat_status)

        receipt = {
            "schema_version": "firmware-free-qemu-runtime-build/v1",
            "status": receipt_status,
            "primary_build_status": "passed",
            "repeat_build_status": repeat_status,
            "host_resources_before_build": resources,
            "host_resources_before_optional_repeat": second_resource_report,
            "source_identity": {
                "repository": UPSTREAM,
                "commit": UPSTREAM_COMMIT,
                "projection_digest": reference["integrationSource"]["projectionDigest"],
                "source_lock_changed": reference["integrationSource"]["sourceLockChanged"],
                "firmware_tree_fetched": False,
                "reviewed_file_sha256": source_hashes,
                "reviewed_file_bytes": source_sizes,
                "build_input_manifest_sha256": input_manifest_sha256,
            },
            "base_image": base,
            "qemu_source_review": debian,
            "license_review": license_report,
            "build": {
                "qemu_version": QEMU_VERSION,
                "qemu_descriptor_sha256": QEMU_DSC_SHA256,
                "qemu_archives": debian["source_archives"],
                "qemu_patch_sha256": source_hashes[
                    "emulator/docker/qemu/snowsky-disc-devices.patch"
                ],
                "qemu_configure_flags": list(QEMU_CONFIGURE_FLAGS),
                "shim_recipe_sha256": source_hashes["emulator/shims/build_shims.sh"],
                "shim_source_sha256": {
                    name: source_hashes[f"emulator/shims/{name}"]
                    for name in (
                        "asndshim.c",
                        "asound.cards",
                        "capture.h",
                        "fbshim.c",
                        "mqshim.c",
                        "tinyshim.c",
                    )
                },
                "artifact_sha256_and_elf": first["artifacts"],
                "debian_snapshot_inrelease": first["debian_snapshot_inrelease"],
                "debian_archive_keyring_sha256": first["debian_archive_keyring_sha256"],
                "installed_package_bom_sha256": first["package_bom_sha256"],
                "installed_package_count": first["package_count"],
                "installed_packages": first["installed_packages"],
                "toolchain": first["toolchain"],
                "container_limits": first["limits"],
                "build_logs": first["build_logs"],
                "elapsed_seconds": first_elapsed,
                "temporary_container_cleanup": "verified",
                "repeated_clean_build_comparison": repeat,
            },
            "network_boundary": (
                "Dependency fetches used the pinned GitHub source files, the dated Debian "
                "snapshot in debian.sources, and the exact Debian base image registry digest. "
                "GitHub-hosted runner networking is not network-level egress isolation."
            ),
            "apt_sandbox": (
                "APT ran as container UID 0 because SETUID/SETGID capabilities are dropped; "
                "fakeroot simulated dpkg file ownership metadata from two packages downloaded "
                "through the signed pinned snapshot, avoiding CAP_CHOWN. Dpkg::Use-Pty=false "
                "and Dir::Log=/dev/null avoid APT's term.log ownership change; explicit audit "
                "logs retain diagnostics. The container retained --cap-drop=ALL and "
                "no-new-privileges."
            ),
            "runtime_and_device_boundaries": {
                "firmware_processed": False,
                "qemu_executable_invoked": False,
                "guest_booted": False,
                "binfmt_registered": False,
                "runtime_image_built": False,
                "container_image_published": False,
                "compiled_binary_published": False,
                "usb_or_hardware_accessed": False,
                "compatibility_claimed": False,
            },
            "elapsed_seconds": round(time.monotonic() - started, 1),
        }
    write_summary("Firmware-free QEMU and MIPS shim build", receipt)


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"preflight", "build", "measure"}:
        print("usage: qemu_runtime_build.py {preflight|build|measure}", file=sys.stderr)
        return 2
    try:
        if sys.argv[1] == "preflight":
            preflight()
        elif sys.argv[1] == "build":
            build()
        else:
            measure_build_evidence()
    except (StopBuild, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        message = str(exc).replace(str(ROOT), "<workspace>")
        print(f"PREBUILD_STOP: {message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
