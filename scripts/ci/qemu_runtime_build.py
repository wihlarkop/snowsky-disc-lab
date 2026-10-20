#!/usr/bin/env python3
"""Bounded firmware-free QEMU runtime build checks for the hosted PR runner."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
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
        "source-download.log",
        "source-extract.log",
    )
)
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
    if reference.get("integrationSource", {}).get("commit") != UPSTREAM_COMMIT:
        raise StopBuild("M1-01 QEMU source identity differs from the workflow pin")
    inputs = reference.get("buildInputs", {})
    if inputs.get("baseImage", {}).get("reference") != BASE_IMAGE:
        raise StopBuild("M1-01 base image reference differs from the workflow pin")
    if inputs.get("baseImage", {}).get("platformManifest") != f"sha256:{BASE_AMD64_MANIFEST}":
        raise StopBuild("M1-01 amd64 base manifest differs from the workflow pin")
    qemu = inputs.get("qemu", {})
    if (
        qemu.get("debianSourceVersion") != QEMU_VERSION
        or qemu.get("sourceDescriptor", {}).get("sha256") != QEMU_DSC_SHA256
    ):
        raise StopBuild("M1-01 Debian QEMU source identity differs from the workflow pin")
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
                "Estimate for a pinned two-stage QEMU source build, Debian toolchain "
                "packages, final runtime image layers, and 2 GiB disk headroom."
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
    command = (
        r"""
set -euo pipefail
install -d -m 0700 /audit
export DEBIAN_FRONTEND=noninteractive
apt_opts=(
  -o APT::Sandbox::User=root
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
apt-get "${apt_opts[@]}" update >/audit/apt-update.log 2>&1
keyring=/usr/share/keyrings/debian-archive-keyring.gpg
sha256sum "$keyring" | awk '{print $1}' > /audit/archive-keyring-before.sha256
for f in /var/lib/apt/lists/*_InRelease; do
  status="$(gpgv --status-fd 1 --keyring "$keyring" "$f" 2>&1)"
  fingerprint="$(printf '%s\n' "$status" | awk '$2 == "VALIDSIG" {print $3; exit}')"
  test -n "$fingerprint"
  codename="$(grep -m1 '^Codename:' "$f" | cut -d: -f2- | xargs)"
  test -n "$codename"
  file_hash="$(sha256sum "$f" | awk '{print $1}')"
  printf '%s\t%s\t%s\t%s\n' \
    "$(basename "$f")" "$codename" "$fingerprint" "$file_hash" \
    >> /audit/inrelease.tsv
done
apt-get "${apt_opts[@]}" install -y --no-install-recommends dpkg-dev >/audit/apt-install.log 2>&1
sha256sum "$keyring" | awk '{print $1}' > /audit/archive-keyring-after.sha256
cmp /audit/archive-keyring-before.sha256 /audit/archive-keyring-after.sha256
install -d -m 0700 /audit/source
source_tmp="$(mktemp -d /tmp/qemu-source-download.XXXXXX)"
cd "$source_tmp"
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
dpkg-source -x /audit/source/qemu_7.2+dfsg-7+deb12u18.dsc /audit/unpacked \
  >/audit/source-extract.log 2>&1
test -f /audit/unpacked/debian/copyright
sha256sum /audit/unpacked/debian/copyright > /audit/debian-copyright.sha256
find /audit/unpacked -maxdepth 1 -type f -name 'COPYING*' -print0 \
  | sort -z \
  | xargs -0 -r sha256sum > /audit/copying-hashes.txt
"""
    )
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
            try:
                copy_audit_files(container_name, audit_dir, AUDIT_LOG_FILES, required=False)
            except (StopBuild, OSError, subprocess.SubprocessError):
                pass
            diagnostics = read_audit_diagnostics(audit_dir)
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
            if lines:
                diagnostics = lines[-10:]
    return diagnostics


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
    license_fields = sorted(
        set(
            line.split(":", 1)[1].strip()
            for line in copyright_text.splitlines()
            if line.startswith("License:")
        )
    )
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
        "debian_copyright_license_field_count": len(license_fields),
        "debian_copyright_license_labels": [label[:160] for label in license_fields[:80]],
        "top_level_copying_file_hashes": [
            line.strip()
            for line in (audit_dir / "copying-hashes.txt").read_text(encoding="utf-8").splitlines()
        ],
    }


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


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] != "preflight":
        print("usage: qemu_runtime_build.py preflight", file=sys.stderr)
        return 2
    try:
        preflight()
    except (StopBuild, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        message = str(exc).replace(str(ROOT), "<workspace>")
        print(f"PREBUILD_STOP: {message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
