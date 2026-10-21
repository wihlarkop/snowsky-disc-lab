"""Boundary regressions; Docker is simulated here, hosted acceptance executes QEMU."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from snowsky_disc_lab import synthetic_runtime as runtime


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    directory = tmp_path / "inputs"
    directory.mkdir(mode=0o711)
    for name in (
        "qemu-mipsel",
        "mips32le-execution-smoke.elf",
        "mips32le-posix-mqueue.elf",
    ):
        (directory / name).write_bytes(name.encode())
        (directory / name).chmod(0o555)
    qemu_hash = hashlib.sha256(b"qemu-mipsel").hexdigest()
    monkeypatch.setattr(runtime, "QEMU_SHA256", qemu_hash)
    evidence = {
        "artifacts": [{"name": "qemu-mipsel", "sha256": qemu_hash}],
        "synthetic_guest": {
            "source": {"sha256": runtime.GUEST_SOURCE_SHA256},
            "elf": {"sha256": hashlib.sha256(b"mips32le-execution-smoke.elf").hexdigest()},
        },
        "synthetic_queue_guest": {
            "source": {"sha256": runtime.MQUEUE_GUEST_SOURCE_SHA256},
            "elf": {"sha256": hashlib.sha256(b"mips32le-posix-mqueue.elf").hexdigest()},
        },
    }
    return directory, evidence


class Docker:
    def __init__(self):
        self.calls = []
        self.inspection: list[dict[str, Any]] = []
        self.mode = "filesystem"
        self.timeout = False
        self.extra_mount = False
        self.foreign_owner = False
        self.cleanup_failure = False
        self.mqueue_failure = False
        self.mqueue_timeout = False

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if args[1] == "create":
            self.mode = args[-1]
            label = args[args.index("--label") + 1].split("=", 1)
            mounts = []
            for index, arg in enumerate(args):
                if arg == "--mount":
                    fields = dict(
                        part.split("=", 1) for part in args[index + 1].split(",") if "=" in part
                    )
                    mounts.append(
                        {
                            "Type": "bind",
                            "Source": fields["src"],
                            "Destination": fields["dst"],
                            "RW": False,
                        }
                    )
            if self.extra_mount:
                mounts.append(
                    {"Type": "bind", "Source": "/home", "Destination": "/host", "RW": True}
                )
            self.inspection = [
                {
                    "Id": "a" * 64,
                    "Config": {
                        "Image": runtime.BASE_IMAGE,
                        "User": "65534:65534",
                        "Labels": {label[0]: "foreign" if self.foreign_owner else label[1]},
                        "Entrypoint": None,
                        "Cmd": args[-5:],
                        "WorkingDir": "",
                        "Env": [
                            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                        ],
                    },
                    "HostConfig": {
                        "NetworkMode": "none",
                        "CapDrop": ["ALL"],
                        "CapAdd": None,
                        "SecurityOpt": ["no-new-privileges:true"],
                        "ReadonlyRootfs": True,
                        "Privileged": False,
                        "Memory": 256 * 1024**2,
                        "MemorySwap": 256 * 1024**2,
                        "NanoCpus": 1_000_000_000,
                        "PidsLimit": 16,
                        "Devices": [],
                        "DeviceRequests": None,
                        "PortBindings": {},
                        "PidMode": "",
                        "IpcMode": "none",
                        "UTSMode": "",
                        "VolumesFrom": None,
                        "DeviceCgroupRules": None,
                        "Tmpfs": runtime.TMPFS,
                    },
                    "Mounts": mounts,
                    "State": {"Running": False, "ExitCode": 0, "OOMKilled": False},
                }
            ]
            return subprocess.CompletedProcess(args, 0, "a" * 64 + "\n")
        if args[1] == "inspect":
            return subprocess.CompletedProcess(args, 0, json.dumps(self.inspection))
        if args[1] == "start":
            if self.timeout:
                raise subprocess.TimeoutExpired(args, kwargs["timeout"])
            output = {
                "filesystem": runtime.EXPECTED_OUTPUT,
                "failure": "SNOWSKY_MIPS32LE_EXPECTED_FAILURE\n",
                "timeout": "",
                "mqueue-first": runtime.MQUEUE_FIRST_OUTPUT,
                "mqueue-second": runtime.MQUEUE_SECOND_OUTPUT,
            }[self.mode]
            code = {
                "filesystem": 0,
                "failure": 23,
                "timeout": 124,
                "mqueue-first": 0,
                "mqueue-second": 0,
            }[self.mode]
            if self.mqueue_failure and self.mode == "mqueue-first":
                output = (
                    "QUEUE_PROBE=first\n"
                    "MQ_ERROR_STAGE=exclusive_create\n"
                    "MQ_ERROR_NAME=EPERM\n"
                    "MQ_ERROR_ERRNO=1\n"
                )
                code = 40
            if self.mqueue_timeout and self.mode == "mqueue-first":
                output = ""
                code = 124
            self.inspection[0]["State"]["ExitCode"] = code
            return subprocess.CompletedProcess(args, code, output)
        if args[1] == "rm":
            return subprocess.CompletedProcess(args, int(self.cleanup_failure), "")
        raise AssertionError(args)


def test_real_session_flow_and_no_replace(inputs, tmp_path, monkeypatch):
    docker = Docker()
    monkeypatch.setattr(runtime, "_docker", docker)
    store = tmp_path / "sessions"
    receipt = runtime.launch(*inputs, store, session_id="one")
    assert receipt["status"] == "passed"
    assert receipt["execution"]["exit_code"] == 0
    assert receipt["cleanup"]["container_removed"] is True
    assert receipt["execution"]["observations"]["readonly_write_errno"] == 30
    assert str(tmp_path) not in json.dumps(receipt)
    with pytest.raises(runtime.RuntimeRefused, match="existing"):
        runtime.launch(*inputs, store, session_id="one")
    assert len([call for call in docker.calls if call[1] == "create"]) == 1
    second = runtime.launch(*inputs, store, session_id="two")
    assert second["session_id"] != receipt["session_id"]
    assert (store / "one" / "receipt.json").is_file()


@pytest.mark.parametrize("mode,code", [("failure", 23), ("timeout", 124)])
def test_expected_guest_lifecycle(inputs, tmp_path, monkeypatch, mode, code):
    monkeypatch.setattr(runtime, "_docker", Docker())
    receipt = runtime.launch(*inputs, tmp_path / "sessions", _case=mode)
    assert receipt["execution"]["exit_code"] == code
    assert receipt["execution"]["timed_out"] is (mode == "timeout")
    assert receipt["cleanup"]["container_removed"]


def test_posix_mqueue_cases_use_fixed_guest_and_bounded_qemu_syscall_trace():
    command = runtime.COMMAND

    assert "mqueue-first) guest=/inputs/mips32le-posix-mqueue.elf; option=first" in command
    assert "mqueue-second) guest=/inputs/mips32le-posix-mqueue.elf; option=second" in command
    assert "QEMU_STRACE=1 timeout" in command
    assert "-le 8192" in command
    assert "mq_open mq_getsetattr mq_timedsend mq_timedreceive mq_unlink close" in command
    assert "/dev/mqueue" not in command
    assert "/ui" not in command and "/player" not in command
    assert "ulimit -q" not in command and "setrlimit" not in command


@pytest.mark.parametrize("state", ["extra_mount", "foreign_owner"])
def test_inspect_refuses_before_start(inputs, tmp_path, monkeypatch, state):
    docker = Docker()
    setattr(docker, state, True)
    monkeypatch.setattr(runtime, "_docker", docker)
    with pytest.raises(runtime.RuntimeRefused):
        runtime.launch(*inputs, tmp_path / "sessions")
    assert not any(call[1] == "start" for call in docker.calls)
    if state == "foreign_owner":
        assert not any(call[1] == "rm" for call in docker.calls)


def test_outer_timeout_quarantines_and_removes_only_owned_container(inputs, tmp_path, monkeypatch):
    docker = Docker()
    docker.timeout = True
    monkeypatch.setattr(runtime, "_docker", docker)
    with pytest.raises(runtime.RuntimeRefused, match="deadline"):
        runtime.launch(*inputs, tmp_path / "sessions", session_id="timeout")
    receipt = json.loads((tmp_path / "sessions/timeout/receipt.json").read_text())
    assert receipt["status"] == "quarantined"
    assert receipt["cleanup"]["container_removed"]
    assert docker.calls[-1] == ["docker", "rm", "--force", "a" * 64]


def test_cleanup_failure_is_not_reported_as_success(inputs, tmp_path, monkeypatch):
    docker = Docker()
    docker.cleanup_failure = True
    monkeypatch.setattr(runtime, "_docker", docker)
    with pytest.raises(runtime.RuntimeRefused, match="cleanup"):
        runtime.launch(*inputs, tmp_path / "sessions", session_id="failed")
    receipt = json.loads((tmp_path / "sessions/failed/receipt.json").read_text())
    assert receipt["status"] == "quarantined"
    assert receipt["cleanup"]["container_removed"] is False


@pytest.mark.parametrize("name", ["../escape", "/absolute", "a/b", "a,b", "", "a\\b"])
def test_unsafe_session_names_refused(inputs, tmp_path, name):
    with pytest.raises(runtime.RuntimeRefused):
        runtime.launch(*inputs, tmp_path / "sessions", session_id=name)
    assert not (tmp_path / "sessions").exists()


def test_changed_artifact_and_unknown_source_refused(inputs, tmp_path):
    directory, evidence = inputs
    evidence["synthetic_guest"]["source"]["sha256"] = "0" * 64
    with pytest.raises(runtime.RuntimeRefused, match="identity"):
        runtime.launch(directory, evidence, tmp_path / "sessions")
    evidence["synthetic_guest"]["source"]["sha256"] = runtime.GUEST_SOURCE_SHA256
    (directory / "qemu-mipsel").chmod(0o644)
    (directory / "qemu-mipsel").write_bytes(b"changed")
    with pytest.raises(runtime.RuntimeRefused, match="identity"):
        runtime.launch(directory, evidence, tmp_path / "sessions")


def test_symlink_ancestor_is_refused(inputs, tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable for this account")
    with pytest.raises(runtime.RuntimeRefused, match="path"):
        runtime.launch(*inputs, link / "sessions")
    assert not (target / "sessions").exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("NetworkMode", "host"),
        ("Privileged", True),
        ("CapAdd", ["SYS_ADMIN"]),
        ("PidMode", "host"),
        ("IpcMode", "host"),
        ("ReadonlyRootfs", False),
        ("Memory", 0),
        ("DeviceCgroupRules", ["a *:* rwm"]),
        ("Tmpfs", {"/host": "rw"}),
        ("SecurityOpt", ["seccomp=unconfined"]),
    ],
)
def test_actual_inspect_security_drift_refused(inputs, tmp_path, monkeypatch, field, value):
    docker = Docker()

    def altered(args, **kwargs):
        result = docker(args, **kwargs)
        if args[1] == "inspect":
            docker.inspection[0]["HostConfig"][field] = value
            result.stdout = json.dumps(docker.inspection)
        return result

    monkeypatch.setattr(runtime, "_docker", altered)
    with pytest.raises(runtime.RuntimeRefused):
        runtime.launch(*inputs, tmp_path / "sessions")
    assert not any(call[1] == "start" for call in docker.calls)


def test_wrong_bind_source_refused(inputs, tmp_path, monkeypatch):
    docker = Docker()

    def altered(args, **kwargs):
        result = docker(args, **kwargs)
        if args[1] == "inspect":
            docker.inspection[0]["Mounts"][0]["Source"] = "/unexpected-source"
            result.stdout = json.dumps(docker.inspection)
        return result

    monkeypatch.setattr(runtime, "_docker", altered)
    with pytest.raises(runtime.RuntimeRefused, match="mount source"):
        runtime.launch(*inputs, tmp_path / "sessions")
    assert not any(call[1] == "start" for call in docker.calls)


def test_synthetic_input_is_measured_and_revalidated(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    for name, data in runtime.LAYOUT.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o444)
    first = runtime._verify_layout(root)
    assert len(first) == 64
    marker = root / "etc/lab-marker"
    marker.chmod(0o644)
    marker.write_bytes(b"modified")
    with pytest.raises(runtime.RuntimeRefused):
        runtime._verify_layout(root)


def test_fixture_source_pin_matches_checkout():
    from pathlib import Path

    source = Path(__file__).resolve().parents[1] / "scripts/ci/fixtures/mips32le_execution_smoke.c"
    assert hashlib.sha256(source.read_bytes()).hexdigest() == runtime.GUEST_SOURCE_SHA256


def test_posix_mqueue_fixture_source_pin_matches_checkout():
    source = Path(__file__).resolve().parents[1] / "scripts/ci/fixtures/mips32le_posix_mqueue.c"
    assert hashlib.sha256(source.read_bytes()).hexdigest() == runtime.MQUEUE_GUEST_SOURCE_SHA256


def test_posix_mqueue_acceptance_records_two_clean_private_sessions(inputs, tmp_path, monkeypatch):
    docker = Docker()
    monkeypatch.setattr(runtime, "_docker", docker)
    store = tmp_path / "sessions"

    receipt = runtime.posix_mqueue_acceptance(*inputs, store)

    assert receipt["schema_version"] == "firmware-free-mips32le-posix-mqueue-acceptance/v1"
    assert receipt["status"] == "passed"
    assert receipt["queue"]["name"] == runtime.MQUEUE_NAME
    assert receipt["queue"]["attributes"] == runtime.MQUEUE_ATTRIBUTES
    assert receipt["queue"]["payload_sha256"] == runtime.MQUEUE_PAYLOAD_SHA256
    assert len(receipt["sessions"]) == 2
    first, second = receipt["sessions"]
    assert first["session_identity"] != second["session_identity"]
    assert first["cleanup"]["container_removed"] is True
    assert second["cleanup"]["container_removed"] is True
    assert receipt["observed_syscalls"]["first_session"]["mq_open_duplicate_exclusive"] == {
        "result": -1,
        "errno": "EEXIST",
        "errno_number": 17,
    }
    assert receipt["observed_syscalls"]["first_session"]["mq_timedreceive_empty_queue"] == {
        "result": -1,
        "errno": "EAGAIN",
        "errno_number": 11,
    }
    assert receipt["observed_syscalls"]["first_session"]["retained_queue_empty_receive"] == {
        "result": -1,
        "errno": "EAGAIN",
        "errno_number": 11,
    }
    assert receipt["observed_syscalls"]["first_session"]["mq_open_after_unlink"]["errno"] == (
        "ENOENT"
    )
    assert receipt["observed_syscalls"]["first_session"]["qemu_strace_syscalls"] == [
        "mq_open",
        "mq_getsetattr",
        "mq_timedsend",
        "mq_timedreceive",
        "mq_unlink",
        "close",
    ]
    assert receipt["observed_syscalls"]["second_session"]["mq_timedreceive_empty_queue"] == {
        "result": -1,
        "errno": "EAGAIN",
        "errno_number": 11,
    }
    assert receipt["session_separation"]["first_container_removed_before_second_create"]
    assert receipt["session_separation"]["second_session_same_name_o_excl_create"] == "success"
    assert receipt["cleanup"]["persistent_shared_queue"] is False
    assert receipt["stock_compatibility"]["stock_v257_queue_attributes"] == (
        "DOCUMENTED_ONLY_UNVERIFIED"
    )
    assert (store / "posix-mqueue-acceptance.json").is_file()
    create_indexes = [i for i, call in enumerate(docker.calls) if call[1] == "create"]
    remove_indexes = [i for i, call in enumerate(docker.calls) if call[1:3] == ["rm", "--force"]]
    assert len(create_indexes) == len(remove_indexes) == 2
    assert remove_indexes[0] < create_indexes[1]
    for call_index in create_indexes:
        args = docker.calls[call_index]
        assert args[args.index("--ipc") + 1] == "none"
        assert args[args.index("--network") + 1] == "none"
        assert "--cap-drop=ALL" in args
        assert "--privileged" not in args
        assert not any("/dev/mqueue" in item for item in args)
    assert str(tmp_path) not in json.dumps(receipt)
    assert "/ui" not in json.dumps(receipt)
    assert "/player" not in json.dumps(receipt)


def test_posix_mqueue_failure_has_only_bounded_errno_evidence(inputs, tmp_path, monkeypatch):
    docker = Docker()
    docker.mqueue_failure = True
    monkeypatch.setattr(runtime, "_docker", docker)

    with pytest.raises(runtime.RuntimeRefused, match="queue acceptance failed") as failure:
        runtime.posix_mqueue_acceptance(*inputs, tmp_path / "sessions")

    receipt = failure.value.receipt
    assert receipt is not None
    assert receipt["schema_version"] == "firmware-free-mips32le-posix-mqueue-acceptance/v1"
    assert receipt["status"] == "failed"
    assert receipt["failure"] == {
        "category": "queue-syscall",
        "stage": "exclusive_create",
        "errno": "EPERM",
        "errno_number": 1,
    }
    assert receipt["sessions"][0]["cleanup"]["container_removed"] is True
    assert receipt["sessions"][0]["execution"]["stdout_bytes"] < 1024
    serialized = json.dumps(receipt)
    assert "MQ_ERROR_STAGE=" not in serialized
    assert str(tmp_path) not in serialized
    assert (tmp_path / "sessions/posix-mqueue-acceptance.json").is_file()


def test_posix_mqueue_failure_reports_sanitized_observed_attributes_and_syscalls():
    output = (
        "QUEUE_PROBE=first\n"
        f"QUEUE_NAME={runtime.MQUEUE_NAME}\n"
        "CREATE=ok\n"
        "MQ_ERROR_STAGE=attributes\n"
        "MQ_ERROR_NAME=NONE\n"
        "MQ_ERROR_ERRNO=0\n"
        "MQ_OBSERVED_MAX_MESSAGES=10\n"
        "MQ_OBSERVED_MESSAGE_BYTES=8192\n"
        "MQ_OBSERVED_CURRENT_MESSAGES=0\n"
        "MQ_OBSERVED_FLAGS=0\n"
        "MQ_OBSERVED_MODE=0600\n"
        "QEMU_SYSCALL_TRACE=mq_open,mq_getsetattr\n"
    )

    failure = runtime._mqueue_failure(output)

    assert failure == {
        "stage": "attributes",
        "errno": "NONE",
        "errno_number": 0,
        "completed_operations": ["mq_open_create"],
        "observed_attributes": {
            "max_messages": 10,
            "max_message_bytes": 8192,
            "current_messages": 0,
            "flags": 0,
            "mode": "0600",
        },
        "qemu_strace_syscalls": ["mq_open", "mq_getsetattr"],
    }
    receipt = runtime._mqueue_receipt(
        evidence={
            "synthetic_queue_guest": {
                "source": {"sha256": runtime.MQUEUE_GUEST_SOURCE_SHA256},
                "elf": {"sha256": "a" * 64},
            }
        },
        sessions=[{"execution": {"queue_syscall_error": failure}}],
        status="failed",
    )
    assert receipt["failure"] == {"category": "queue-syscall", **failure}
    assert "MQ_OBSERVED_MAX_MESSAGES=" not in json.dumps(receipt)

    mode_failure = runtime._mqueue_failure(
        "MQ_ERROR_STAGE=mode\nMQ_ERROR_NAME=NONE\nMQ_ERROR_ERRNO=0\nMQ_OBSERVED_MODE=0640\n"
    )
    assert mode_failure == {
        "stage": "mode",
        "errno": "NONE",
        "errno_number": 0,
        "observed_attributes": {"mode": "0640"},
    }


def test_posix_mqueue_deadline_failure_is_sanitized_and_cleans_container(
    inputs, tmp_path, monkeypatch
):
    docker = Docker()
    docker.mqueue_timeout = True
    monkeypatch.setattr(runtime, "_docker", docker)

    with pytest.raises(runtime.RuntimeRefused, match="queue acceptance failed") as failure:
        runtime.posix_mqueue_acceptance(*inputs, tmp_path / "sessions")

    receipt = failure.value.receipt
    assert receipt is not None
    assert receipt["failure"] == {
        "category": "queue-timeout",
        "stage": "guest_deadline",
        "errno": "NONE",
        "errno_number": 0,
    }
    assert receipt["sessions"][0]["execution"]["timed_out"] is True
    assert receipt["sessions"][0]["cleanup"]["container_removed"] is True


def test_acceptance_retention_is_globally_bounded(tmp_path):
    parent = tmp_path / "runtime"
    stores = [runtime.reserve_acceptance_store(parent) for _ in range(8)]
    assert len(set(stores)) == 8
    with pytest.raises(runtime.RuntimeRefused, match="retention"):
        runtime.reserve_acceptance_store(parent)
    assert len(list(parent.iterdir())) == 8


def test_workflow_manual_dispatch_and_pr_guards_are_narrow():
    import yaml

    path = Path(__file__).resolve().parents[1] / ".github/workflows/synthetic-runtime.yml"
    workflow = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"pull_request", "workflow_dispatch"}
    assert workflow["on"]["workflow_dispatch"] == ""
    job = workflow["jobs"]["synthetic-runtime"]
    guard = job["if"]
    assert guard == (
        "(github.event_name == 'pull_request' &&\n"
        " github.repository == 'wihlarkop/snowsky-disc-lab' &&\n"
        " github.event.pull_request.head.repo.full_name == 'wihlarkop/snowsky-disc-lab' &&\n"
        " github.event.pull_request.head.ref == 'codex/mips32le-posix-mqueue') ||\n"
        "(github.event_name == 'workflow_dispatch' &&\n"
        " github.repository == 'wihlarkop/snowsky-disc-lab' &&\n"
        " github.ref == 'refs/heads/main')"
    )
    assert "inputs." not in guard
    assert workflow["permissions"] == {"contents": "read"}
    assert job["timeout-minutes"] == "45"
    steps = job["steps"]
    assert len(steps) == 2
    checkout = steps[0]
    assert checkout["uses"].endswith("@11bd71901bbe5b1630ceea73d27597364c9af683")
    assert "github.event.pull_request.head.sha" in checkout["with"]["ref"]
    assert "github.sha" in checkout["with"]["ref"]
    assert checkout["with"]["persist-credentials"] == "false"
    assert steps[1]["run"] == "python3 scripts/ci/qemu_runtime_build.py session"
    source = path.read_text(encoding="utf-8")
    assert "inputs:" not in source
    assert "inputs." not in source
    assert "secrets." not in source
    assert "push:" not in source
    assert "scripts/ci/fixtures/mips32le_posix_mqueue.c" in workflow["on"]["pull_request"]["paths"]
