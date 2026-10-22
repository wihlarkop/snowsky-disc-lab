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

from . import synthetic_ipc_handoff as ipc_handoff
from . import synthetic_ipc_supervision as ipc_supervision
from . import synthetic_ui

BASE_IMAGE = (
    "docker.io/library/debian:12@sha256:"
    "6ebd97fa83deb272194a2cf015b3d26a4d538e9ad3a7a79d544c8af5b0a01443"
)
# Measured on main fecc939, manual execution-smoke run 39464385240.
QEMU_SHA256 = "2a58998c25a7836b910f255641a95e9d828967c75ed6b0de2e5490cb82038ddb"
GUEST_SOURCE_SHA256 = "d00aee44bbcf9a38cbf1a710fa5187501666dd280db4a7fe62ee1c91a1b18661"
MQUEUE_GUEST_SOURCE_SHA256 = "459656e8b14e24c2ab1f2ab97d2219c978b290203168d20e6c8a8554c0ae6795"
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
    "ATTRIBUTES_EMPTY_RECEIVE=EAGAIN:11\n"
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
    "RETAINED_ATTRIBUTES_EMPTY_RECEIVE=EAGAIN:11\n"
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
    "ATTRIBUTES_EMPTY_RECEIVE=EAGAIN:11\n"
    "CLOSE=ok\n"
    "UNLINK=ok\n"
    "REOPEN_AFTER_UNLINK=ENOENT:2\n"
    "QEMU_SYSCALL_TRACE=mq_open,mq_getsetattr,mq_timedreceive,mq_unlink,close\n"
)
MQUEUE_ERROR_STAGES = frozenset(
    {
        "exclusive_create",
        "mq_getattr",
        "attributes",
        "fstat_mode",
        "mode",
        "nonblock_empty_receive",
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
if [ "$1" = "ipc-handoff" ]; then
  set +e
  QEMU_STRACE=1 timeout --signal=TERM --kill-after=1s 5s \
    /inputs/qemu-mipsel /inputs/mips32le-posix-ipc-handoff.elf consumer \
    > /session-diagnostics/consumer.stdout 2> /session-diagnostics/consumer.stderr &
  consumer_pid=$!
  QEMU_STRACE=1 timeout --signal=TERM --kill-after=1s 5s \
    /inputs/qemu-mipsel /inputs/mips32le-posix-ipc-handoff.elf producer \
    > /session-diagnostics/producer.stdout 2> /session-diagnostics/producer.stderr &
  producer_pid=$!
  wait "$consumer_pid"
  consumer_code=$?
  wait "$producer_pid"
  producer_code=$?
  set -e
  test "$(wc -c < /session-diagnostics/consumer.stdout)" -le 512 || exit 98
  test "$(wc -c < /session-diagnostics/producer.stdout)" -le 512 || exit 98
  test "$(wc -c < /session-diagnostics/consumer.stderr)" -le 8192 || exit 97
  test "$(wc -c < /session-diagnostics/producer.stderr)" -le 8192 || exit 97
  trace_calls_for() {
    trace_calls=""
    for syscall in mq_open mq_getsetattr mq_timedsend mq_timedreceive mq_unlink close; do
      if grep -Eq " ${syscall}\\(" "$1"; then
        if [ -n "$trace_calls" ]; then trace_calls="$trace_calls,"; fi
        trace_calls="${trace_calls}${syscall}"
      fi
    done
    printf '%s' "$trace_calls"
  }
  consumer_trace="$(trace_calls_for /session-diagnostics/consumer.stderr)"
  producer_trace="$(trace_calls_for /session-diagnostics/producer.stderr)"
  printf 'HANDOFF_CONTAINER_SESSION=single\n'
  printf 'GUEST_EXIT_CODE_CONSUMER=%s\n' "$consumer_code"
  cat /session-diagnostics/consumer.stdout
  printf 'GUEST_EXIT_CODE_PRODUCER=%s\n' "$producer_code"
  cat /session-diagnostics/producer.stdout
  printf 'QEMU_SYSCALL_TRACE_CONSUMER=%s\n' "$consumer_trace"
  printf 'QEMU_SYSCALL_TRACE_PRODUCER=%s\n' "$producer_trace"
  if [ "$consumer_code" -ne 0 ] || [ "$producer_code" -ne 0 ]; then exit 40; fi
  exit 0
fi
if [ "$1" = "ipc-supervision" ]; then
  role_status_reason() {
    case "$1" in
      143) printf 'signal:TERM' ;;
      137) printf 'signal:KILL' ;;
      *) printf 'exit:%s' "$1" ;;
    esac
  }
  run_supervised_case() {
    scenario="$1"
    deadline="$2"
    consumer_file="/session-diagnostics/${scenario}-consumer"
    producer_file="/session-diagnostics/${scenario}-producer"
    consumer_pending=yes
    producer_pending=yes
    timer_pending=yes
    grace_pending=no
    deadline_expired=no
    consumer_status=255
    producer_status=255
    consumer_reason=not-started
    producer_reason=not-started
    term_roles=none
    kill_roles=none
    consumer_started=no
    producer_started=no
    consumer_pid=0
    producer_pid=0
    case "$scenario" in
      normal)
        failure_kind=none; failure_role=none; failure_reason=none
        protocol=request-ack-verified
        ;;
      consumer-exits-before-request)
        failure_kind=guest-exit; failure_role=consumer; failure_reason=exit:42
        protocol=consumer-exit-before-request
        ;;
      producer-exits-before-ack)
        failure_kind=guest-exit; failure_role=producer; failure_reason=exit:43
        protocol=producer-exit-before-ack
        ;;
      producer-exceeds-deadline)
        failure_kind=deadline; failure_role=producer; failure_reason=deadline
        protocol=producer-deadline-exceeded
        ;;
      producer-failure-cancels-sibling)
        failure_kind=guest-exit; failure_role=producer; failure_reason=exit:44
        protocol=producer-failure-cancelled-consumer
        ;;
      *) exit 99 ;;
    esac
    start_consumer() {
      if [ "$scenario" = normal ]; then
        QEMU_STRACE=1 /inputs/qemu-mipsel /inputs/mips32le-posix-ipc-handoff.elf consumer \
          > "${consumer_file}.stdout" 2> "${consumer_file}.stderr" &
      else
        /inputs/qemu-mipsel /inputs/mips32le-posix-ipc-supervision.elf consumer "$scenario" \
          > "${consumer_file}.stdout" 2> "${consumer_file}.stderr" &
      fi
      consumer_pid=$!
    }
    start_producer() {
      if [ "$scenario" = normal ]; then
        QEMU_STRACE=1 /inputs/qemu-mipsel /inputs/mips32le-posix-ipc-handoff.elf producer \
          > "${producer_file}.stdout" 2> "${producer_file}.stderr" &
      else
        /inputs/qemu-mipsel /inputs/mips32le-posix-ipc-supervision.elf producer "$scenario" \
          > "${producer_file}.stdout" 2> "${producer_file}.stderr" &
      fi
      producer_pid=$!
    }
    wait_for_child_marker() {
      marker="$1"
      output_file="$2"
      child_pid="$3"
      attempt=0
      while [ "$attempt" -lt 100 ]; do
        if grep -Fxq "$marker" "$output_file" 2>/dev/null; then return 0; fi
        if ! kill -0 "$child_pid" 2>/dev/null; then return 1; fi
        sleep 0.02
        attempt=$((attempt + 1))
      done
      return 1
    }
    sleep "$deadline" &
    timer_pid=$!
    if [ "$scenario" = consumer-exits-before-request ]; then
      start_producer
      wait_for_child_marker 'SYNTHETIC_SUPERVISION_ROLE=producer' \
        "${producer_file}.stdout" "$producer_pid" || exit 93
      start_consumer
    elif [ "$scenario" = producer-failure-cancels-sibling ]; then
      start_consumer
      wait_for_child_marker 'SYNTHETIC_SUPERVISION_ROLE=consumer' \
        "${consumer_file}.stdout" "$consumer_pid" || exit 93
      start_producer
    else
      start_consumer
      start_producer
    fi
    wait_event() {
      wait_targets=()
      if [ "$consumer_pending" = yes ]; then wait_targets+=("$consumer_pid"); fi
      if [ "$producer_pending" = yes ]; then wait_targets+=("$producer_pid"); fi
      if [ "$timer_pending" = yes ]; then wait_targets+=("$timer_pid"); fi
      if [ "$grace_pending" = yes ]; then wait_targets+=("$grace_pid"); fi
      unset event_pid
      set +e
      wait -n -p event_pid "${wait_targets[@]}"
      event_status=$?
      set -e
    }
    record_guest_status() {
      if [ "$event_pid" = "$consumer_pid" ]; then
        consumer_pending=no
        consumer_status="$event_status"
        consumer_reason="$(role_status_reason "$event_status")"
      elif [ "$event_pid" = "$producer_pid" ]; then
        producer_pending=no
        producer_status="$event_status"
        producer_reason="$(role_status_reason "$event_status")"
      else
        exit 96
      fi
    }
    reap_after_missed_signal() {
      missed_role="$1"
      missed_pid="$2"
      set +e
      wait "$missed_pid"
      missed_status=$?
      set -e
      if [ "$missed_role" = consumer ]; then
        consumer_pending=no
        consumer_status="$missed_status"
        consumer_reason="$(role_status_reason "$missed_status")"
      else
        producer_pending=no
        producer_status="$missed_status"
        producer_reason="$(role_status_reason "$missed_status")"
      fi
    }
    stop_timer() {
      if [ "$timer_pending" = yes ]; then
        kill "$timer_pid" 2>/dev/null || true
        wait "$timer_pid" 2>/dev/null || true
        timer_pending=no
      fi
    }
    reap_completed_children() {
      if [ "$consumer_pending" = yes ] && ! jobs -pr | grep -Fxq "$consumer_pid"; then
        set +e
        wait "$consumer_pid"
        completed_status=$?
        set -e
        consumer_pending=no
        consumer_status="$completed_status"
        consumer_reason="$(role_status_reason "$completed_status")"
      fi
      if [ "$producer_pending" = yes ] && ! jobs -pr | grep -Fxq "$producer_pid"; then
        set +e
        wait "$producer_pid"
        completed_status=$?
        set -e
        producer_pending=no
        producer_status="$completed_status"
        producer_reason="$(role_status_reason "$completed_status")"
      fi
    }
    send_term_to_pending() {
      if [ "$consumer_pending" = yes ]; then
        if kill -TERM "$consumer_pid" 2>/dev/null; then
          term_roles=consumer
        else
          reap_after_missed_signal consumer "$consumer_pid"
        fi
      fi
      if [ "$producer_pending" = yes ]; then
        if kill -TERM "$producer_pid" 2>/dev/null; then
          if [ "$term_roles" = none ]; then
            term_roles=producer
          else
            term_roles="${term_roles},producer"
          fi
        else
          reap_after_missed_signal producer "$producer_pid"
        fi
      fi
    }
    start_grace_if_needed() {
      if [ "$consumer_pending" = yes ] || [ "$producer_pending" = yes ]; then
        sleep 1 &
        grace_pid=$!
        grace_pending=yes
      fi
    }
    while [ "$consumer_pending" = yes ] || [ "$producer_pending" = yes ]; do
      wait_event
      if [ "$timer_pending" = yes ] && [ "$event_pid" = "$timer_pid" ]; then
        timer_pending=no
        reap_completed_children
        if [ "$consumer_pending" = yes ] || [ "$producer_pending" = yes ]; then
          deadline_expired=yes
          send_term_to_pending
          start_grace_if_needed
        fi
      elif [ "$grace_pending" = yes ] && [ "$event_pid" = "$grace_pid" ]; then
        grace_pending=no
        reap_completed_children
        if [ "$consumer_pending" = yes ]; then
          if kill -KILL "$consumer_pid" 2>/dev/null; then
            kill_roles=consumer
          else
            reap_after_missed_signal consumer "$consumer_pid"
          fi
        fi
        if [ "$producer_pending" = yes ]; then
          if kill -KILL "$producer_pid" 2>/dev/null; then
            if [ "$kill_roles" = none ]; then
              kill_roles=producer
            else
              kill_roles="${kill_roles},producer"
            fi
          else
            reap_after_missed_signal producer "$producer_pid"
          fi
        fi
      else
        record_guest_status
        if [ "$scenario" != normal ] || [ "$event_status" -ne 0 ]; then
          if [ "$timer_pending" = yes ]; then stop_timer; fi
          if [ "$term_roles" = none ]; then
            send_term_to_pending
            start_grace_if_needed
          fi
        fi
      fi
    done
    stop_timer
    if [ "$grace_pending" = yes ]; then
      kill "$grace_pid" 2>/dev/null || true
      wait "$grace_pid" 2>/dev/null || true
      grace_pending=no
    fi
    test "$(wc -c < "${consumer_file}.stdout")" -le 512 || exit 98
    test "$(wc -c < "${producer_file}.stdout")" -le 512 || exit 98
    test "$(wc -c < "${consumer_file}.stderr")" -le 8192 || exit 97
    test "$(wc -c < "${producer_file}.stderr")" -le 8192 || exit 97
    consumer_hash="$(sha256sum "${consumer_file}.stdout" | cut -d ' ' -f 1)"
    producer_hash="$(sha256sum "${producer_file}.stdout" | cut -d ' ' -f 1)"
    if [ "$scenario" = normal ]; then
      consumer_expected='HANDOFF_ROLE=consumer'
      producer_expected='HANDOFF_ROLE=producer'
    else
      consumer_expected='SYNTHETIC_SUPERVISION_ROLE=consumer'
      producer_expected='SYNTHETIC_SUPERVISION_ROLE=producer'
    fi
    if head -n 1 "${consumer_file}.stdout" | grep -Fxq "$consumer_expected"; then
      consumer_started=yes
    fi
    if head -n 1 "${producer_file}.stdout" | grep -Fxq "$producer_expected"; then
      producer_started=yes
    fi
    test "$consumer_started" = yes && test "$producer_started" = yes || exit 93
    if [ "$consumer_status" -eq 143 ]; then test "$consumer_reason" = signal:TERM || exit 92; fi
    if [ "$consumer_status" -eq 137 ]; then test "$consumer_reason" = signal:KILL || exit 92; fi
    if [ "$producer_status" -eq 143 ]; then test "$producer_reason" = signal:TERM || exit 92; fi
    if [ "$producer_status" -eq 137 ]; then test "$producer_reason" = signal:KILL || exit 92; fi
    printf 'SUPERVISION_CASE=%s\n' "$scenario"
    printf 'SUPERVISION_CONSUMER_PID=%s\n' "$consumer_pid"
    printf 'SUPERVISION_CONSUMER_STATUS=%s\n' "$consumer_status"
    printf 'SUPERVISION_CONSUMER_EXIT_REASON=%s\n' "$consumer_reason"
    printf 'SUPERVISION_CONSUMER_OUTPUT_SHA256=%s\n' "$consumer_hash"
    printf 'SUPERVISION_CONSUMER_STARTED=%s\n' "$consumer_started"
    printf 'SUPERVISION_PRODUCER_PID=%s\n' "$producer_pid"
    printf 'SUPERVISION_PRODUCER_STATUS=%s\n' "$producer_status"
    printf 'SUPERVISION_PRODUCER_EXIT_REASON=%s\n' "$producer_reason"
    printf 'SUPERVISION_PRODUCER_OUTPUT_SHA256=%s\n' "$producer_hash"
    printf 'SUPERVISION_PRODUCER_STARTED=%s\n' "$producer_started"
    printf 'SUPERVISION_FAILURE_KIND=%s\n' "$failure_kind"
    printf 'SUPERVISION_FAILURE_ROLE=%s\n' "$failure_role"
    printf 'SUPERVISION_FAILURE_REASON=%s\n' "$failure_reason"
    printf 'SUPERVISION_DEADLINE_SECONDS=%s\n' "$deadline"
    printf 'SUPERVISION_DEADLINE_EXPIRED=%s\n' "$deadline_expired"
    printf 'SUPERVISION_TERM_SENT=%s\n' "$term_roles"
    printf 'SUPERVISION_KILL_SENT=%s\n' "$kill_roles"
    printf 'SUPERVISION_CHILDREN_REAPED=yes\n'
    printf 'SUPERVISION_PROTOCOL=%s\n' "$protocol"
    printf 'SUPERVISION_CASE_END\n'
  }
  run_supervised_case normal 5
  run_supervised_case consumer-exits-before-request 5
  run_supervised_case producer-exits-before-ack 5
  run_supervised_case producer-exceeds-deadline 2
  run_supervised_case producer-failure-cancels-sibling 5
  exit 0
fi
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
    handoff_guest = evidence.get("synthetic_ipc_handoff_guest", {})
    if handoff_guest.get("source", {}).get("sha256") != ipc_handoff.GUEST_SOURCE_SHA256:
        raise RuntimeRefused("POSIX handoff source identity is not the reviewed fixture")
    supervision_guest = evidence.get("synthetic_ipc_supervision_guest", {})
    if supervision_guest.get("source", {}).get("sha256") != ipc_supervision.GUEST_SOURCE_SHA256:
        raise RuntimeRefused("POSIX supervision source identity is not the reviewed fixture")
    ui_guest = evidence.get("synthetic_ui_guest")
    if (
        ui_guest is not None
        and ui_guest.get("source", {}).get("sha256") != synthetic_ui.GUEST_SOURCE_SHA256
    ):
        raise RuntimeRefused("synthetic UI source identity is not reviewed")
    qemu = [item for item in evidence.get("artifacts", []) if item.get("name") == "qemu-mipsel"]
    if len(qemu) != 1 or qemu[0].get("sha256") != QEMU_SHA256:
        raise RuntimeRefused("QEMU identity is not the reviewed interpreter")
    expected = {
        "qemu-mipsel": QEMU_SHA256,
        "mips32le-execution-smoke.elf": guest.get("elf", {}).get("sha256", ""),
        "mips32le-posix-mqueue.elf": queue_guest.get("elf", {}).get("sha256", ""),
        ipc_handoff.GUEST_ELF: handoff_guest.get("elf", {}).get("sha256", ""),
        ipc_supervision.GUEST_ELF: supervision_guest.get("elf", {}).get("sha256", ""),
    }
    if ui_guest is not None:
        expected[synthetic_ui.GUEST_ELF] = ui_guest.get("elf", {}).get("sha256", "")
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
            ("ATTRIBUTES_EMPTY_RECEIVE=EAGAIN:11", "mq_timedreceive_empty_queue"),
            ("DUPLICATE_CREATE=EEXIST:17", "mq_open_duplicate_exclusive"),
            ("SEND=ok", "mq_timedsend"),
            ("RECEIVE=ok", "mq_timedreceive"),
            ("CLOSE=ok", "mq_close"),
            ("UNLINK=ok", "mq_unlink"),
            ("REOPEN_AFTER_UNLINK=ENOENT:2", "mq_open_after_unlink"),
            ("RECREATE=ok", "mq_open_recreate"),
            (
                "RETAINED_ATTRIBUTES_EMPTY_RECEIVE=EAGAIN:11",
                "mq_timedreceive_retained_empty_queue",
            ),
            ("RETAINED_CLOSE=ok", "mq_close_retained"),
            ("QUEUE_LINKED_AT_EXIT=yes", "queue_linked_at_exit"),
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
    command = COMMAND
    if case in synthetic_ui.CASES:
        command = COMMAND.replace(
            "ulimit -f 64\n",
            "ulimit -f 64\n" + synthetic_ui.COMMAND.replace("__UI_SESSION_TOKEN__", token),
        )
    return [*args, BASE_IMAGE, "/bin/bash", "-euc", command, "--", case]


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
    if _case not in {
        "filesystem",
        "failure",
        "timeout",
        "mqueue-first",
        "mqueue-second",
        "ipc-handoff",
        "ipc-supervision",
        *synthetic_ui.CASES,
    }:
        raise RuntimeRefused("unknown first-party synthetic case")
    if _case in synthetic_ui.CASES and "synthetic_ui_guest" not in build_evidence:
        raise RuntimeRefused("synthetic UI guest build evidence is required")
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
        "handoff_guest_source_sha256": ipc_handoff.GUEST_SOURCE_SHA256,
        "supervision_guest_source_sha256": ipc_supervision.GUEST_SOURCE_SHA256,
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
            "ipc-handoff": 0,
            "ipc-supervision": 0,
            **dict.fromkeys(synthetic_ui.CASES, 0),
        }[_case]
        expected_output = {
            "filesystem": EXPECTED_OUTPUT,
            "failure": "SNOWSKY_MIPS32LE_EXPECTED_FAILURE\n",
            "timeout": "",
            "mqueue-first": MQUEUE_FIRST_OUTPUT,
            "mqueue-second": MQUEUE_SECOND_OUTPUT,
            "ipc-handoff": ipc_handoff.EXPECTED_CONTAINER_OUTPUT,
            "ipc-supervision": None,
            **dict.fromkeys(synthetic_ui.CASES),
        }[_case]
        if _case in synthetic_ui.CASES:
            observations = synthetic_ui.parse_execution_output(result.stdout, _case, token)
            receipt["execution"] = {
                "exit_code": result.returncode,
                "duration_seconds": elapsed,
                "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
                "stdout_bytes": len(result.stdout.encode()),
                "timed_out": False,
                "terminated": state.get("Running") is False,
                "ui": observations,
            }
        if _case == "ipc-handoff":
            handoff_observations = ipc_handoff.parse_execution_output(result.stdout)
            receipt["execution"] = {
                "exit_code": result.returncode,
                "duration_seconds": elapsed,
                "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
                "stdout_bytes": len(result.stdout.encode()),
                "timed_out": result.returncode == 124,
                "terminated": state.get("Running") is False,
                "guest_exit_codes": handoff_observations.get("guest_exit_codes", {}),
                "handoff": handoff_observations,
            }
            if handoff_observations.get("status") != "passed":
                failure = handoff_observations.get("failure", {})
                raise RuntimeRefused(
                    "synthetic IPC handoff failed at "
                    f"{failure.get('stage', 'output_mismatch')}: "
                    f"{failure.get('errno', 'NONE')} ({failure.get('errno_number', 0)})"
                )
        if _case == "ipc-supervision":
            supervision_observations = ipc_supervision.parse_execution_output(
                result.stdout, wrapper_exit_code=result.returncode
            )
            receipt["execution"] = {
                "exit_code": result.returncode,
                "duration_seconds": elapsed,
                "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
                "stdout_bytes": len(result.stdout.encode()),
                "timed_out": False,
                "terminated": state.get("Running") is False,
                "supervision": supervision_observations,
            }
            if supervision_observations.get("status") != "passed":
                failure = supervision_observations.get("failure", {})
                raise RuntimeRefused(
                    "synthetic IPC supervision failed at "
                    f"{failure.get('category', 'guest-observation')}: "
                    f"{failure.get('stage', 'output_mismatch')}"
                )
        if _case.startswith("mqueue-"):
            queue_error = _mqueue_failure(result.stdout)
            if queue_error is None and result.returncode == 124:
                queue_error = {"stage": "guest_deadline", "errno": "NONE", "errno_number": 0}
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
                if queue_error["stage"] == "guest_deadline":
                    raise RuntimeRefused("POSIX queue guest exceeded its bounded deadline")
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
            or (
                _case not in {"ipc-supervision", *synthetic_ui.CASES}
                and result.stdout != expected_output
            )
        ):
            raise RuntimeRefused("guest output, exit or termination differs from the fixed case")
        if not _case.startswith("mqueue-") and _case not in {
            "ipc-handoff",
            "ipc-supervision",
            *synthetic_ui.CASES,
        }:
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
                owned_state = _inspect(container_id)
                if not _owned(owned_state, token):
                    raise RuntimeRefused("container ownership changed; cleanup refused")
                state = owned_state.get("State", {})
                stop_command_result = "not-needed"
                if state.get("Running") is True:
                    stopped = _docker(["docker", "stop", "--time", "1", container_id])
                    if stopped.returncode:
                        stop_command_result = "failed"
                    else:
                        stop_command_result = "succeeded"
                    owned_state = _inspect(container_id)
                    if not _owned(owned_state, token):
                        raise RuntimeRefused("container ownership changed; cleanup refused")
                removed = _docker(["docker", "rm", "--force", container_id])
                if removed.returncode:
                    raise RuntimeRefused("owned container cleanup failed")
                receipt["cleanup"] = {
                    "container_removed": True,
                    "container_stopped": True,
                    "ownership_verified_before_removal": True,
                    "container_stop_command": stop_command_result,
                    "private_tmpfs_released": True,
                    "host_metadata": "retained; no recursive cleanup",
                }
                receipt["lifecycle"].append("removed")
                if stop_command_result == "failed":
                    failure = failure or (
                        "owned container graceful stop failed; exact-container cleanup completed"
                    )
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
                    "mq_timedreceive_empty_queue": {
                        "result": -1,
                        "errno": "EAGAIN",
                        "errno_number": 11,
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
                    "retained_queue_empty_receive": {
                        "result": -1,
                        "errno": "EAGAIN",
                        "errno_number": 11,
                    },
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
                    "mq_timedreceive_empty_queue": {
                        "result": -1,
                        "errno": "EAGAIN",
                        "errno_number": 11,
                    },
                    "fstat_mode": "0600",
                    "mq_close": "success",
                    "mq_unlink": "success",
                    "mq_open_after_unlink": {"result": -1, "errno": "ENOENT", "errno_number": 2},
                    "qemu_strace_syscalls": [
                        "mq_open",
                        "mq_getsetattr",
                        "mq_timedreceive",
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
            {
                "category": "queue-timeout"
                if error.get("stage") == "guest_deadline"
                else "queue-syscall",
                **error,
            }
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
    handoff_receipt = ipc_handoff.acceptance(inputs, evidence, store)
    supervision_receipt = ipc_supervision.acceptance(inputs, evidence, store)
    ui_receipt = (
        synthetic_ui.acceptance(inputs, evidence, store)
        if "synthetic_ui_guest" in evidence
        else None
    )
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
        "synthetic_ipc_handoff": handoff_receipt,
        "synthetic_ipc_supervision": supervision_receipt,
        "synthetic_ui": ui_receipt,
        "unsupported_or_unverified": first["unsupported_or_unverified"],
    }
