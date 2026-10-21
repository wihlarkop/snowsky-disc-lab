"""One fixed firmware-free QEMU session; no arbitrary commands or rootfs execution.

The reviewed build supplies measured artifacts directly. This is an internal launch
phase, not an artifact-import API. A trusted, quiescent host filesystem and Docker
daemon are assumed. QEMU user mode shares the container/host kernel.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import time
import uuid
from itertools import islice
from pathlib import Path
from typing import Any

BASE_IMAGE = (
    "docker.io/library/debian:12@sha256:"
    "6ebd97fa83deb272194a2cf015b3d26a4d538e9ad3a7a79d544c8af5b0a01443"
)
# Measured on main fecc939, manual execution-smoke run 39464385240.
QEMU_SHA256 = "2a58998c25a7836b910f255641a95e9d828967c75ed6b0de2e5490cb82038ddb"
GUEST_SOURCE_SHA256 = "d00aee44bbcf9a38cbf1a710fa5187501666dd280db4a7fe62ee1c91a1b18661"
MQUEUE_GUEST_SOURCE_SHA256 = "d5f643630197568842393b4abc20c25de50c5712b2c3c0550846af1be6006d7e"
MQUEUE_NAME = "/snowsky_disc_lab_mqueue_probe_v1"
MQUEUE_PAYLOAD = b"SNOWSKY_MIPS32LE_POSIX_MQ_V1"
MQUEUE_PAYLOAD_SHA256 = "b8e0b0e98d2906e4b1d5cdaf72e10f44468760938a4c004c85fcbb7a4160e206"
MQUEUE_PRIORITY = 7
MQUEUE_ATTRIBUTES = {
    "max_messages": 2,
    "max_message_bytes": 64,
    "current_messages": 0,
    "open_flags": ["O_CREAT", "O_EXCL", "O_NONBLOCK", "O_RDWR"],
    "mode": "0600",
}
MQUEUE_FIRST_OUTPUT = (
    "QUEUE_PROBE=first\n"
    f"QUEUE_NAME={MQUEUE_NAME}\n"
    "CREATE=ok\n"
    "ATTRIBUTES=maxmsg:2,msgsize:64,curmsgs:0,nonblock:true\n"
    "ATTRIBUTES_MODE=0600\n"
    "DUPLICATE_CREATE=EEXIST:17\n"
    "SEND=ok\n"
    "RECEIVE=ok\n"
    f"PAYLOAD_BYTES={len(MQUEUE_PAYLOAD)}\n"
    f"PAYLOAD_SHA256={MQUEUE_PAYLOAD_SHA256}\n"
    f"PRIORITY={MQUEUE_PRIORITY}\n"
    "CLOSE=ok\n"
    "UNLINK=ok\n"
    "REOPEN_AFTER_UNLINK=ENOENT:2\n"
    "RECREATE=ok\n"
    "RETAINED_ATTRIBUTES=maxmsg:2,msgsize:64,curmsgs:0,nonblock:true\n"
    "RETAINED_ATTRIBUTES_MODE=0600\n"
    "RETAINED_CLOSE=ok\n"
    "QUEUE_LINKED_AT_EXIT=yes\n"
    "QEMU_SYSCALL_TRACE=mq_open,mq_getsetattr,mq_timedsend,mq_timedreceive,mq_unlink,close\n"
)
MQUEUE_SECOND_OUTPUT = (
    "QUEUE_PROBE=second\n"
    f"QUEUE_NAME={MQUEUE_NAME}\n"
    "CREATE=ok\n"
    "ATTRIBUTES=maxmsg:2,msgsize:64,curmsgs:0,nonblock:true\n"
    "ATTRIBUTES_MODE=0600\n"
    "CLOSE=ok\n"
    "UNLINK=ok\n"
    "REOPEN_AFTER_UNLINK=ENOENT:2\n"
    "QEMU_SYSCALL_TRACE=mq_open,mq_getsetattr,mq_unlink,close\n"
)
MQUEUE_ERROR_STAGES = frozenset(
    {
        "exclusive_create",
        "mq_getattr",
        "attributes",
        "fstat_mode",
        "mode",
        "duplicate_exclusive_create",
        "mq_send",
        "mq_receive_verify",
        "mq_close_initial",
        "mq_unlink_initial",
        "reopen_after_unlink",
        "mq_close_retained",
        "mq_close_second",
        "mq_unlink_second",
        "fixed_argument",
    }
)
MQUEUE_ERRNO_NAMES = {
    0: "NONE",
    1: "EPERM",
    2: "ENOENT",
    5: "EIO",
    9: "EBADF",
    11: "EAGAIN",
    12: "ENOMEM",
    13: "EACCES",
    17: "EEXIST",
    22: "EINVAL",
    23: "ENFILE",
    24: "EMFILE",
    28: "ENOSPC",
    38: "ENOSYS",
}
MQUEUE_TRACE_SYSCALLS = (
    "mq_open",
    "mq_getsetattr",
    "mq_timedsend",
    "mq_timedreceive",
    "mq_unlink",
    "close",
)
LABEL = "org.snowsky-disc-lab.synthetic-session"
TMPFS = {
    path: "rw,nosuid,nodev,noexec,size=1m,mode=0700,uid=65534,gid=65534"
    for path in ("/session-data", "/session-tmp", "/session-diagnostics")
}
LAYOUT = {
    "etc/lab-marker": b"SNOWSKY_SYNTHETIC_ROOTFS_V1\n",
    "usr/share/lab/README": b"Synthetic immutable inputs; not mounted firmware.\n",
    "usr/data/UNIMPLEMENTED": b"Synthetic role only; private data lives at /session-data.\n",
    "tmp/UNIMPLEMENTED": b"Synthetic role only; runtime temporary files use /session-tmp.\n",
    "dev/UNIMPLEMENTED": b"No device emulation or hardware passthrough.\n",
    "proc/UNIMPLEMENTED": b"No emulated guest procfs; Docker uses the host kernel.\n",
    "sys/UNIMPLEMENTED": b"No emulated guest sysfs.\n",
}
EXPECTED_OUTPUT = (
    "input_read=ok\nreadonly_write_errno=30\nprivate_create_read=ok\n"
    "temporary_create_read=ok\noutside_write_errno=30\n"
    "host_path_errno=2\nfresh_session=ok\n"
)
COMMAND = r"""set -eu
umask 077
ulimit -c 0
ulimit -f 64
    case "$1" in
 filesystem)
   guest=/inputs/mips32le-execution-smoke.elf
   option=--filesystem; deadline=5s; trace=0
   ;;
 failure) guest=/inputs/mips32le-execution-smoke.elf; option=--fail; deadline=5s; trace=0 ;;
 timeout) guest=/inputs/mips32le-execution-smoke.elf; option=--timeout; deadline=2s; trace=0 ;;
 mqueue-first) guest=/inputs/mips32le-posix-mqueue.elf; option=first; deadline=5s; trace=1 ;;
 mqueue-second) guest=/inputs/mips32le-posix-mqueue.elf; option=second; deadline=5s; trace=1 ;;
 *) exit 99 ;;
esac
set +e
if [ "$trace" = 1 ]; then
  QEMU_STRACE=1 timeout --signal=TERM --kill-after=1s "$deadline" \
    /inputs/qemu-mipsel "$guest" "$option" \
    > /session-diagnostics/stdout 2> /session-diagnostics/stderr
else
  timeout --signal=TERM --kill-after=1s "$deadline" \
    /inputs/qemu-mipsel "$guest" "$option" \
    > /session-diagnostics/stdout 2> /session-diagnostics/stderr
fi
code=$?
set -e
# Only fixed bounded stdout is exported. Unreviewed stderr stays ephemeral.
test "$(wc -c < /session-diagnostics/stdout)" -le 1024 || exit 98
if [ "$trace" = 1 ]; then
  test "$(wc -c < /session-diagnostics/stderr)" -le 8192 || exit 97
  trace_calls=""
  for syscall in mq_open mq_getsetattr mq_timedsend mq_timedreceive mq_unlink close; do
    if grep -Eq " ${syscall}\\(" /session-diagnostics/stderr; then
      if [ -n "$trace_calls" ]; then trace_calls="$trace_calls,"; fi
      trace_calls="${trace_calls}${syscall}"
    fi
  done
else
  test ! -s /session-diagnostics/stderr || exit 97
fi
cat /session-diagnostics/stdout
if [ "$trace" = 1 ]; then
  printf 'QEMU_SYSCALL_TRACE=%s\n' "$trace_calls"
fi
exit "$code"
"""


class RuntimeRefused(RuntimeError):
    """Unsafe, ambiguous or unsuccessful fixed synthetic session."""

    receipt: dict[str, Any] | None = None


def _sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _safe_path(path: Path) -> Path:
    # Inspect lexical components BEFORE resolving; resolving first hides links.
    if ".." in path.parts or any(char in str(path) for char in (",", "\n", "\r")):
        raise RuntimeRefused("unsafe runtime path")
    absolute = path.absolute()
    for component in (absolute, *absolute.parents):
        if component.is_symlink() or component.is_junction():
            raise RuntimeRefused("linked runtime path")
        if component.exists() and not component.is_dir():
            raise RuntimeRefused("non-directory runtime path")
    if absolute == Path.home() or absolute == Path(absolute.anchor):
        raise RuntimeRefused("runtime path must be a dedicated directory")
    return absolute


def _verify_inputs(inputs: Path, evidence: dict[str, Any]) -> dict[str, str]:
    inputs = _safe_path(inputs)
    guest = evidence.get("synthetic_guest", {})
    if guest.get("source", {}).get("sha256") != GUEST_SOURCE_SHA256:
        raise RuntimeRefused("synthetic source identity is not the reviewed fixture")
    queue_guest = evidence.get("synthetic_queue_guest", {})
    if queue_guest.get("source", {}).get("sha256") != MQUEUE_GUEST_SOURCE_SHA256:
        raise RuntimeRefused("POSIX queue source identity is not the reviewed fixture")
    qemu = [item for item in evidence.get("artifacts", []) if item.get("name") == "qemu-mipsel"]
    if len(qemu) != 1 or qemu[0].get("sha256") != QEMU_SHA256:
        raise RuntimeRefused("QEMU identity is not the reviewed interpreter")
    expected = {
        "qemu-mipsel": QEMU_SHA256,
        "mips32le-execution-smoke.elf": guest.get("elf", {}).get("sha256", ""),
        "mips32le-posix-mqueue.elf": queue_guest.get("elf", {}).get("sha256", ""),
    }
    if not inputs.is_dir() or {entry.name for entry in inputs.iterdir()} != set(expected):
        raise RuntimeRefused("unexpected runtime inputs")
    for name, sha256 in expected.items():
        path = inputs / name
        metadata = path.lstat()
        if (
            not re.fullmatch(r"[0-9a-f]{64}", sha256)
            or not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or metadata.st_nlink != 1
            or metadata.st_dev != inputs.stat().st_dev
            or metadata.st_size > 150 * 1024**2
            or _sha(path) != sha256
        ):
            raise RuntimeRefused("runtime artifact identity or path is unsafe")
        if os.name == "posix" and (metadata.st_mode & 0o222 or not metadata.st_mode & 0o111):
            raise RuntimeRefused("runtime artifact permissions are unsafe")
    return expected


def _mqueue_failure(output: str) -> dict[str, Any] | None:
    """Parse only fixed queue outcomes, bounded numeric attributes and syscall names."""
    encoded = output.encode("utf-8", errors="replace")
    if len(encoded) > 1024 or not output.isascii():
        return None
    fields: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in fields:
            continue
        fields[key] = value
    stage = fields.get("MQ_ERROR_STAGE", "")
    name = fields.get("MQ_ERROR_NAME", "")
    number_text = fields.get("MQ_ERROR_ERRNO", "")
    if (
        stage not in MQUEUE_ERROR_STAGES
        or not re.fullmatch(r"[A-Z]{2,12}", name)
        or not re.fullmatch(r"[0-9]{1,4}", number_text)
    ):
        return None
    number = int(number_text)
    if number > 4095 or MQUEUE_ERRNO_NAMES.get(number, "OTHER") != name:
        return None
    failure: dict[str, Any] = {"stage": stage, "errno": name, "errno_number": number}
    observed_attributes: dict[str, int | str] = {}
    for key, label in (
        ("MQ_OBSERVED_MAX_MESSAGES", "max_messages"),
        ("MQ_OBSERVED_MESSAGE_BYTES", "max_message_bytes"),
        ("MQ_OBSERVED_CURRENT_MESSAGES", "current_messages"),
        ("MQ_OBSERVED_FLAGS", "flags"),
    ):
        value = fields.get(key, "")
        if not re.fullmatch(r"[0-9]{1,6}", value) or int(value) > 65535:
            observed_attributes.clear()
            break
        observed_attributes[label] = int(value)
    mode = fields.get("MQ_OBSERVED_MODE", "")
    if re.fullmatch(r"0[0-7]{3}", mode):
        observed_attributes["mode"] = mode
    if observed_attributes:
        failure["observed_attributes"] = observed_attributes

    lines = set(output.splitlines())
    completed_operations = [
        operation
        for marker, operation in (
            ("CREATE=ok", "mq_open_create"),
            ("DUPLICATE_CREATE=EEXIST:17", "mq_open_duplicate_exclusive"),
            ("SEND=ok", "mq_timedsend"),
            ("RECEIVE=ok", "mq_timedreceive"),
            ("CLOSE=ok", "mq_close"),
            ("UNLINK=ok", "mq_unlink"),
            ("REOPEN_AFTER_UNLINK=ENOENT:2", "mq_open_after_unlink"),
            ("RECREATE=ok", "mq_open_recreate"),
        )
        if marker in lines
    ]
    if completed_operations:
        failure["completed_operations"] = completed_operations

    trace = fields.get("QEMU_SYSCALL_TRACE")
    if trace is not None:
        trace_names = trace.split(",") if trace else []
        canonical_trace = [name for name in MQUEUE_TRACE_SYSCALLS if name in trace_names]
        if len(trace_names) == len(set(trace_names)) and trace_names == canonical_trace:
            failure["qemu_strace_syscalls"] = trace_names
    return failure


def _verify_layout(root: Path) -> str:
    _safe_path(root)
    files: dict[str, bytes] = {}
    for index, path in enumerate(root.rglob("*")):
        metadata = path.lstat()
        if (
            index >= 32
            or path.is_symlink()
            or path.is_junction()
            or metadata.st_dev != root.stat().st_dev
        ):
            raise RuntimeRefused("unsafe synthetic input layout")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        name = path.relative_to(root).as_posix()
        if (
            name not in LAYOUT
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != len(LAYOUT[name])
            or (os.name == "posix" and metadata.st_mode & 0o222)
        ):
            raise RuntimeRefused("unexpected synthetic input file or permissions")
        files[name] = path.read_bytes()
        if files[name] != LAYOUT[name]:
            raise RuntimeRefused("synthetic input identity changed")
    if set(files) != set(LAYOUT):
        raise RuntimeRefused("synthetic input layout is incomplete")
    return hashlib.sha256(
        b"".join(name.encode() + b"\0" + data for name, data in sorted(files.items()))
    ).hexdigest()


def reserve_acceptance_store(parent: Path) -> Path:
    """Bound retained metadata across invocations before any expensive build."""
    parent = _safe_path(parent)
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix" and (
        parent.stat().st_uid != os.getuid() or parent.stat().st_mode & 0o077
    ):
        raise RuntimeRefused("runtime retention parent is not private and owned")
    if sum(1 for _ in islice(parent.iterdir(), 8)) >= 8:
        raise RuntimeRefused("runtime retention quota reached; review retained owned sessions")
    store = parent / uuid.uuid4().hex
    store.mkdir(mode=0o700)
    return store


def _docker(args: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    # Commands and guest stdout are bounded; raw daemon diagnostics are never published.
    return subprocess.run(args, check=False, text=True, capture_output=True, timeout=timeout)


def _inspect(container_id: str) -> dict[str, Any]:
    result = _docker(["docker", "inspect", container_id])
    try:
        items = json.loads(result.stdout)
        if result.returncode or not isinstance(items, list) or len(items) != 1:
            raise ValueError
        item = items[0]
        if not isinstance(item, dict) or item.get("Id") != container_id:
            raise ValueError
        if any(not isinstance(item.get(key), dict) for key in ("Config", "HostConfig", "State")):
            raise ValueError
        return item
    except (ValueError, TypeError, IndexError) as exc:
        raise RuntimeRefused("container inspection is invalid") from exc


def _owned(item: dict[str, Any], token: str) -> bool:
    config = item.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    return isinstance(labels, dict) and labels.get(LABEL) == token


def container_args(inputs: Path, rootfs: Path, token: str, case: str) -> list[str]:
    args = [
        "docker",
        "create",
        "--name",
        f"disc-lab-synthetic-{token}",
        "--label",
        f"{LABEL}={token}",
        "--network",
        "none",
        "--ipc",
        "none",
        "--cap-drop=ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--read-only",
        "--user",
        "65534:65534",
        "--pids-limit",
        "16",
        "--memory",
        "256m",
        "--memory-swap",
        "256m",
        "--cpus",
        "1",
    ]
    for target, options in TMPFS.items():
        args += ["--tmpfs", f"{target}:{options}"]
    for source, target in ((inputs, "/inputs"), (rootfs, "/synthetic-rootfs")):
        args += ["--mount", f"type=bind,src={source},dst={target},readonly"]
    return [*args, BASE_IMAGE, "/bin/bash", "-euc", COMMAND, "--", case]


def validate_container(
    item: dict[str, Any], inputs: Path, rootfs: Path, token: str, args: list[str]
) -> dict[str, Any]:
    host, config = item.get("HostConfig", {}), item.get("Config", {})
    required = {
        "NetworkMode": "none",
        "CapDrop": ["ALL"],
        "ReadonlyRootfs": True,
        "Privileged": False,
        "Memory": 256 * 1024**2,
        "MemorySwap": 256 * 1024**2,
        "NanoCpus": 1_000_000_000,
        "PidsLimit": 16,
        "IpcMode": "none",
        "Tmpfs": TMPFS,
    }
    if (
        not _owned(item, token)
        or any(host.get(key) != value for key, value in required.items())
        or host.get("SecurityOpt") != ["no-new-privileges:true"]
        or config.get("Image") != BASE_IMAGE
        or config.get("User") != "65534:65534"
        or config.get("Entrypoint") not in (None, [])
        or config.get("Cmd") != args[-5:]
        or config.get("WorkingDir") not in (None, "")
        or config.get("Env")
        != ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
        or any(
            host.get(key) not in (None, [], {}, "")
            for key in (
                "CapAdd",
                "Devices",
                "DeviceRequests",
                "DeviceCgroupRules",
                "PortBindings",
                "PidMode",
                "UTSMode",
                "UsernsMode",
                "VolumesFrom",
                "Links",
            )
        )
    ):
        raise RuntimeRefused("container isolation differs from the reviewed contract")
    mounts = item.get("Mounts")
    expected = {"/inputs": str(inputs), "/synthetic-rootfs": str(rootfs)}
    seen = set()
    if not isinstance(mounts, list):
        raise RuntimeRefused("invalid runtime mounts")
    for mount in mounts:
        if not isinstance(mount, dict):
            raise RuntimeRefused("invalid runtime mount")
        target = mount.get("Destination")
        if target in seen:
            raise RuntimeRefused("duplicate runtime mount")
        seen.add(target)
        if target in expected:
            if (
                mount.get("Type") != "bind"
                or mount.get("RW") is not False
                or mount.get("Source") != expected[target]
                or mount.get("Propagation") not in (None, "rprivate")
            ):
                raise RuntimeRefused("unexpected runtime mount source or permissions")
        elif (
            target not in TMPFS
            or mount.get("Type") != "tmpfs"
            or mount.get("RW") is not True
            or mount.get("Source") not in (None, "")
        ):
            raise RuntimeRefused("unexpected runtime mount")
    if not set(expected) <= seen:
        raise RuntimeRefused("required runtime mount missing")
    return {
        "mounts": [
            {"source": "<verified-execution-inputs>", "target": "/inputs", "read_only": True},
            {"source": "<owned-synthetic-input>", "target": "/synthetic-rootfs", "read_only": True},
        ],
        "private_writable_tmpfs": dict(TMPFS),
        "verified_host_config": required,
        "all_capabilities_dropped": True,
        "no_new_privileges": True,
        "uid_gid": "65534:65534",
        "host_devices": False,
        "docker_socket": False,
        "host_home": False,
        "shared_source_cache": False,
        "guest_deadline_seconds": 5,
        "timeout_probe_seconds": 2,
        "term_to_kill_grace_seconds": 1,
        "outer_deadline_seconds": 15,
        "stdout_limit_bytes": 1024,
        "diagnostic_file_limit_bytes": 65536,
        "kernel_boundary": "Docker-managed kernel interfaces; QEMU user mode shares host kernel",
    }


def launch(
    inputs: Path,
    build_evidence: dict[str, Any],
    store: Path,
    session_id: str | None = None,
    *,
    _case: str = "filesystem",
) -> dict[str, Any]:
    """Launch only the measured first-party guest; persist sanitized owned metadata.

    Writable guest state is ephemeral tmpfs, not persistent stock userdata. Failure
    retains the small owned session directory as quarantine; no recursive deletion.
    """
    session_id = uuid.uuid4().hex if session_id is None else session_id
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", session_id):
        raise RuntimeRefused("unsafe session identifier")
    if _case not in {"filesystem", "failure", "timeout", "mqueue-first", "mqueue-second"}:
        raise RuntimeRefused("unknown first-party synthetic case")
    identities = _verify_inputs(inputs, build_evidence)
    inputs, store = _safe_path(inputs), _safe_path(store)
    store.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix" and (store.stat().st_uid != os.getuid() or store.stat().st_mode & 0o077):
        raise RuntimeRefused("runtime store is not private and owned")
    # Refuse an unbounded shared store; existing entries are never changed or removed.
    if sum(1 for _ in islice(store.iterdir(), 32)) >= 32:
        raise RuntimeRefused("runtime session store quota exceeded")
    session = store / session_id
    try:
        session.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise RuntimeRefused("existing session identifier; no replacement") from exc
    token = uuid.uuid4().hex
    (session / "owner.json").write_text(json.dumps({"token": token}), encoding="ascii")
    receipt: dict[str, Any] = {
        "schema_version": "firmware-free-synthetic-runtime/v1",
        "status": "quarantined",
        "session_id": session_id,
        "session_identity": token,
        "case": _case,
        "identities": identities,
        "guest_source_sha256": GUEST_SOURCE_SHA256,
        "queue_guest_source_sha256": MQUEUE_GUEST_SOURCE_SHA256,
        "lifecycle": ["reserved"],
        "cleanup": {"container_removed": False},
        "unsupported_or_unverified": [
            "M1-04 stock V2.57 boot",
            "firmware authenticity or compatibility",
            "dynamic vendor loader",
            "persistent stock userdata",
            "emulated proc/sys/devices",
            "guest kernel or full guest mount namespace",
            "audio/framebuffer/UI/hardware",
            "Windows/WSL2 runtime acceptance",
            "arbitrary binary isolation",
        ],
    }
    container_id = None
    failure = None
    try:
        rootfs = session / "synthetic-input"
        rootfs.mkdir(mode=0o755)
        for relative, content in LAYOUT.items():
            path = rootfs / relative
            path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o444)
        receipt["synthetic_input_sha256"] = _verify_layout(rootfs)
        args = container_args(inputs, rootfs, token, _case)
        created = _docker(args)
        if created.returncode or not re.fullmatch(r"[0-9a-f]{64}\n?", created.stdout):
            raise RuntimeRefused("container creation failed; retained owned quarantine")
        container_id = created.stdout.strip()
        receipt["lifecycle"].append("created")
        receipt["isolation"] = validate_container(
            _inspect(container_id), inputs, rootfs, token, args
        )
        # Recheck immutable artifacts immediately before start.
        _verify_inputs(inputs, build_evidence)
        _verify_layout(rootfs)
        receipt["lifecycle"].append("validated")
        receipt["lifecycle"].append("start-requested")
        started = time.monotonic()
        try:
            result = _docker(["docker", "start", "--attach", container_id], timeout=15)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeRefused("outer execution deadline exceeded") from exc
        elapsed = round(time.monotonic() - started, 3)
        final = _inspect(container_id)
        state = final.get("State", {})
        expected_code = {
            "filesystem": 0,
            "failure": 23,
            "timeout": 124,
            "mqueue-first": 0,
            "mqueue-second": 0,
        }[_case]
        expected_output = {
            "filesystem": EXPECTED_OUTPUT,
            "failure": "SNOWSKY_MIPS32LE_EXPECTED_FAILURE\n",
            "timeout": "",
            "mqueue-first": MQUEUE_FIRST_OUTPUT,
            "mqueue-second": MQUEUE_SECOND_OUTPUT,
        }[_case]
        if _case.startswith("mqueue-"):
            queue_error = _mqueue_failure(result.stdout)
            receipt["execution"] = {
                "exit_code": result.returncode,
                "duration_seconds": elapsed,
                "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
                "stdout_bytes": len(result.stdout.encode()),
                "timed_out": result.returncode == 124,
                "terminated": state.get("Running") is False,
                "queue_syscall_error": queue_error,
            }
            if queue_error:
                raise RuntimeRefused(
                    "POSIX queue syscall failed at "
                    f"{queue_error['stage']}: {queue_error['errno']} "
                    f"({queue_error['errno_number']})"
                )
        if (
            not _owned(final, token)
            or state.get("Running") is not False
            or state.get("OOMKilled") is not False
            or state.get("ExitCode") != expected_code
            or result.returncode != expected_code
            or result.stdout != expected_output
        ):
            raise RuntimeRefused("guest output, exit or termination differs from the fixed case")
        if not _case.startswith("mqueue-"):
            receipt["execution"] = {
                "exit_code": result.returncode,
                "duration_seconds": elapsed,
                "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
                "stdout_bytes": len(result.stdout.encode()),
                "timed_out": _case == "timeout",
                "terminated": True,
                "observations": {
                    "input_read": "ok",
                    "readonly_write_errno": 30,
                    "private_create_read": "ok",
                    "temporary_create_read": "ok",
                    "outside_write_errno": 30,
                    "host_path_errno": 2,
                    "fresh_session": "ok",
                }
                if _case == "filesystem"
                else {},
            }
        receipt["lifecycle"].append("exited")
        receipt["status"] = "passed"
    except (RuntimeRefused, OSError, subprocess.SubprocessError, ValueError) as exc:
        # Raw Docker errors, output and host paths are deliberately not retained.
        failure = str(exc) if isinstance(exc, RuntimeRefused) else "runtime operation failed"
    finally:
        if container_id:
            try:
                if not _owned(_inspect(container_id), token):
                    raise RuntimeRefused("container ownership changed; cleanup refused")
                removed = _docker(["docker", "rm", "--force", container_id])
                if removed.returncode:
                    raise RuntimeRefused("owned container cleanup failed")
                receipt["cleanup"] = {
                    "container_removed": True,
                    "private_tmpfs_released": True,
                    "host_metadata": "retained; no recursive cleanup",
                }
                receipt["lifecycle"].append("removed")
            except (RuntimeRefused, OSError, subprocess.SubprocessError):
                failure = failure or "owned container cleanup or ownership verification failed"
        if failure:
            receipt["status"] = "quarantined"
            receipt["failure"] = failure
        with (session / "receipt.json").open("x", encoding="utf-8") as stream:
            json.dump(receipt, stream, sort_keys=True, indent=2)
            stream.write("\n")
    if failure:
        error = RuntimeRefused(failure)
        error.receipt = receipt
        raise error
    return receipt


def _mqueue_session_summary(session: dict[str, Any]) -> dict[str, Any]:
    return {
        key: session[key]
        for key in (
            "session_id",
            "session_identity",
            "case",
            "status",
            "lifecycle",
            "execution",
            "isolation",
            "cleanup",
        )
        if key in session
    }


def _mqueue_receipt(
    evidence: dict[str, Any], sessions: list[dict[str, Any]], *, status: str
) -> dict[str, Any]:
    queue_guest = evidence.get("synthetic_queue_guest", {})
    identities = sessions[0].get("identities", {}) if sessions else {}
    first, second = (sessions + [{}, {}])[:2]
    second_execution = second.get("execution", {})
    first_cleanup = first.get("cleanup", {})
    second_cleanup = second.get("cleanup", {})
    same_name_separated = (
        first_cleanup.get("container_removed") is True
        and second.get("case") == "mqueue-second"
        and second_execution.get("exit_code") == 0
        and second.get("status") == "passed"
    )
    result: dict[str, Any] = {
        "schema_version": "firmware-free-mips32le-posix-mqueue-acceptance/v1",
        "status": status,
        "scope": "first-party synthetic POSIX message queue syscall acceptance",
        "queue": {
            "name": MQUEUE_NAME,
            "attributes": dict(MQUEUE_ATTRIBUTES),
            "payload_bytes": len(MQUEUE_PAYLOAD),
            "payload_sha256": MQUEUE_PAYLOAD_SHA256,
            "priority": MQUEUE_PRIORITY,
        },
        "identities": {
            "qemu_mipsel_sha256": identities.get("qemu-mipsel"),
            "queue_guest_source_sha256": queue_guest.get("source", {}).get("sha256"),
            "queue_guest_elf_sha256": queue_guest.get("elf", {}).get("sha256"),
        },
        "sessions": [_mqueue_session_summary(session) for session in sessions],
        "observed_syscalls": (
            {
                "first_session": {
                    "mq_open_exclusive_create": "success",
                    "mq_getattr": {
                        "max_messages": 2,
                        "max_message_bytes": 64,
                        "current_messages": 0,
                        "nonblocking": True,
                    },
                    "fstat_mode": "0600",
                    "mq_open_duplicate_exclusive": {
                        "result": -1,
                        "errno": "EEXIST",
                        "errno_number": 17,
                    },
                    "mq_timedsend": "success",
                    "mq_timedreceive": {
                        "result": "success",
                        "payload_matches": True,
                        "payload_bytes": len(MQUEUE_PAYLOAD),
                        "payload_sha256": MQUEUE_PAYLOAD_SHA256,
                        "priority": MQUEUE_PRIORITY,
                    },
                    "mq_close": "success",
                    "mq_unlink": "success",
                    "mq_open_after_unlink": {"result": -1, "errno": "ENOENT", "errno_number": 2},
                    "mq_open_recreate": "success",
                    "retained_queue_linked_until_exit": True,
                    "qemu_strace_syscalls": [
                        "mq_open",
                        "mq_getsetattr",
                        "mq_timedsend",
                        "mq_timedreceive",
                        "mq_unlink",
                        "close",
                    ],
                },
                "second_session": {
                    "mq_open_exclusive_create": "success",
                    "mq_getattr": {
                        "max_messages": 2,
                        "max_message_bytes": 64,
                        "current_messages": 0,
                        "nonblocking": True,
                    },
                    "fstat_mode": "0600",
                    "mq_close": "success",
                    "mq_unlink": "success",
                    "mq_open_after_unlink": {"result": -1, "errno": "ENOENT", "errno_number": 2},
                    "qemu_strace_syscalls": [
                        "mq_open",
                        "mq_getsetattr",
                        "mq_unlink",
                        "close",
                    ],
                },
            }
            if status == "passed"
            else {"complete_observation": False}
        ),
        "session_separation": {
            "first_container_removed_before_second_create": first_cleanup.get("container_removed")
            is True,
            "distinct_session_identities": bool(
                first.get("session_identity")
                and second.get("session_identity")
                and first.get("session_identity") != second.get("session_identity")
            ),
            "second_session_same_name_o_excl_create": (
                "success" if same_name_separated else "not-established"
            ),
        },
        "isolation": {
            "container_profiles": [
                session.get("isolation") for session in sessions if session.get("isolation")
            ],
            "mqueue_filesystem_mount_added": False,
        },
        "stock_compatibility": {
            "stock_v257_queue_attributes": "DOCUMENTED_ONLY_UNVERIFIED",
            "stock_ipc_compatibility": "UNVERIFIED",
            "m1_04_stock_boot": "NOT RUN",
        },
    }
    if status == "passed":
        result["outputs"] = [
            {
                "session_identity": session.get("session_identity"),
                "bytes": session.get("execution", {}).get("stdout_bytes"),
                "sha256": session.get("execution", {}).get("stdout_sha256"),
                "duration_seconds": session.get("execution", {}).get("duration_seconds"),
            }
            for session in sessions
        ]
        result["cleanup"] = {
            "first_container_removed": first_cleanup.get("container_removed") is True,
            "first_private_tmpfs_released": first_cleanup.get("private_tmpfs_released") is True,
            "second_container_removed": second_cleanup.get("container_removed") is True,
            "second_private_tmpfs_released": second_cleanup.get("private_tmpfs_released") is True,
            "persistent_shared_queue": False,
        }
    else:
        last_execution = sessions[-1].get("execution", {}) if sessions else {}
        error = last_execution.get("queue_syscall_error")
        result["failure"] = (
            {"category": "queue-syscall", **error}
            if isinstance(error, dict)
            else {"category": "fixed-probe-or-container-check-failed"}
        )
    return result


def _persist_mqueue_receipt(store: Path, receipt: dict[str, Any]) -> None:
    path = store / "posix-mqueue-acceptance.json"
    with path.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write("\n")


def posix_mqueue_acceptance(inputs: Path, evidence: dict[str, Any], store: Path) -> dict[str, Any]:
    """Run two serial, owned sessions using only the fixed queue guest cases."""
    sessions: list[dict[str, Any]] = []
    try:
        first = launch(inputs, evidence, store, session_id="mqueue-first", _case="mqueue-first")
        sessions.append(first)
        if first.get("cleanup", {}).get("container_removed") is not True:
            raise RuntimeRefused("first queue container was not removed before session two")
        second = launch(inputs, evidence, store, session_id="mqueue-second", _case="mqueue-second")
        sessions.append(second)
        if first.get("session_identity") == second.get("session_identity"):
            raise RuntimeRefused("queue sessions did not receive separate identities")
        receipt = _mqueue_receipt(evidence, sessions, status="passed")
        if not all(
            item.get("container_removed") is True and item.get("private_tmpfs_released") is True
            for item in (first.get("cleanup", {}), second.get("cleanup", {}))
        ):
            raise RuntimeRefused("queue acceptance container cleanup was incomplete")
    except RuntimeRefused as exc:
        if exc.receipt is not None:
            sessions.append(exc.receipt)
        receipt = _mqueue_receipt(evidence, sessions, status="failed")
        _persist_mqueue_receipt(store, receipt)
        error = RuntimeRefused("POSIX message queue acceptance failed")
        error.receipt = receipt
        raise error from exc
    _persist_mqueue_receipt(store, receipt)
    return receipt


def acceptance(inputs: Path, evidence: dict[str, Any], store: Path) -> dict[str, Any]:
    """Execute the fixed acceptance journey using one freshly measured build."""
    first = launch(inputs, evidence, store, session_id="first")
    try:
        launch(inputs, evidence, store, session_id="first")
    except RuntimeRefused as exc:
        if "existing" not in str(exc):
            raise
    else:
        raise RuntimeRefused("existing-session refusal did not occur")
    for invalid in ("../escape", "/absolute", "a/b"):
        try:
            launch(inputs, evidence, store, session_id=invalid)
        except RuntimeRefused:
            pass
        else:
            raise RuntimeRefused("unsafe-traversal refusal did not occur")
    link = store / "unsafe-link"
    link.symlink_to(inputs, target_is_directory=True)
    try:
        try:
            launch(inputs, evidence, link / "escape")
        except RuntimeRefused:
            pass
        else:
            raise RuntimeRefused("symlink refusal did not occur")
    finally:
        # Remove precisely the link created above, never its target.
        if link.is_symlink():
            link.unlink()
    sessions = [first, launch(inputs, evidence, store, session_id="second")]
    for case in ("failure", "timeout"):
        sessions.append(launch(inputs, evidence, store, session_id=case, _case=case))
    mqueue_receipt = posix_mqueue_acceptance(inputs, evidence, store)
    return {
        "schema_version": "firmware-free-synthetic-runtime-acceptance/v1",
        "status": "passed",
        "identities": first["identities"],
        "guest_source_sha256": GUEST_SOURCE_SHA256,
        "synthetic_input_sha256": first["synthetic_input_sha256"],
        "isolation": first["isolation"],
        "sessions": [
            {
                key: session[key]
                for key in (
                    "session_id",
                    "session_identity",
                    "case",
                    "status",
                    "lifecycle",
                    "execution",
                    "cleanup",
                )
            }
            for session in sessions
        ],
        "host_refusals": ["existing session ID", "unsafe traversal", "symlink ancestor"],
        "session_isolation": (
            "independent inspected containers and tmpfs; both O_EXCL probes passed"
        ),
        "posix_mqueue": mqueue_receipt,
        "unsupported_or_unverified": first["unsupported_or_unverified"],
    }
