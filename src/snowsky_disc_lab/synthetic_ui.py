"""Fixed synthetic input/frame acceptance; no external binary launch authority."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "firmware-free-mips32le-synthetic-ui/v1"
GUEST_SOURCE = "scripts/ci/fixtures/mips32le_synthetic_ui.c"
GUEST_SOURCE_SHA256 = "360f3d19f54c27a3a805a4be00a78a3d6531267306e88319b97dc0cb55b6e13f"
GUEST_ELF = "mips32le-synthetic-ui.elf"
INPUT = b"RIGHT\n"
GEOMETRY = {"width": 16, "height": 8, "stride_bytes": 64, "format": "RGBA8888", "bytes": 512}
CASES = {"ui-normal": 0, "ui-wrong": 41, "ui-missing": 42, "ui-early": 43, "ui-stale": 45}


def frame_bytes(cursor: int) -> bytes:
    """Independent pixel oracle, never used to produce runtime frames."""
    return b"".join(
        bytes((240, 192, 32, 255) if x == cursor else (16, 32, 48, 255))
        for _y in range(8)
        for x in range(16)
    )


FRAME_HASHES = {
    name: hashlib.sha256(frame_bytes(cursor)).hexdigest()
    for name, cursor in (("initial", 2), ("changed", 3))
}

# Two private FIFOs implement the existing fixed wrapper's handoff pattern.
# Readiness is a fresh guest handshake AND a byte observation before input delivery.
# QEMU is under the existing TERM/KILL deadline; wrapper waits the owned child.
COMMAND = r"""
if [[ "$1" == ui-* ]]; then
  token=__UI_SESSION_TOKEN__
  mode=normal
  test "$1" != ui-early || mode=early
  mkfifo -m 0600 /session-tmp/ui-in /session-tmp/ui-out
  exec 3<>/session-tmp/ui-in
  exec 4<>/session-tmp/ui-out
  if [ "$1" = ui-stale ]; then
    printf stale > /session-data/initial.rgba
  fi
  timeout --signal=TERM --kill-after=1s 5s \
    /inputs/qemu-mipsel /inputs/mips32le-synthetic-ui.elf "$token" "$mode" \
    < /session-tmp/ui-in > /session-tmp/ui-out 2>/session-diagnostics/ui.stderr &
  child=$!
  printf 'UI_SESSION=%s\n' "$token"
  ready=no
  if IFS= read -r -t 2 line <&4; then
    test "$line" = "READY $token" || exit 81
    test -f /session-data/initial.rgba && test ! -L /session-data/initial.rgba
    test "$(wc -c < /session-data/initial.rgba)" -eq 512 || exit 82
    printf 'UI_INITIAL='
    od -An -v -tx1 /session-data/initial.rgba | tr -d ' \n'
    printf '\n'
    ready=yes
    case "$1" in
      ui-normal) printf 'RIGHT\n' >&3; printf 'UI_INPUT=RIGHT\n' ;;
      ui-wrong) printf 'WRONG\n' >&3; printf 'UI_INPUT=WRONG\n' ;;
      ui-missing) printf 'UI_INPUT=none\n' ;;
      *) exit 83 ;;
    esac
  fi
  set +e
  wait "$child"
  code=$?
  set -e
  printf 'UI_EXIT=%s\n' "$code"
  if [ "$code" -eq 0 ]; then
    IFS= read -r -t 1 line <&4 || exit 84
    test "$line" = "MOVED $token" || exit 85
    test -f /session-data/changed.rgba && test ! -L /session-data/changed.rgba
    test "$(wc -c < /session-data/changed.rgba)" -eq 512 || exit 86
    printf 'UI_CHANGED='
    od -An -v -tx1 /session-data/changed.rgba | tr -d ' \n'
    printf '\nUI_EVENT=cursor:2->3\n'
  else
    test ! -e /session-data/changed.rgba || exit 87
    printf 'UI_EVENT=rejected\n'
  fi
  test "$(wc -c < /session-diagnostics/ui.stderr)" -le 1024 || exit 88
  exec 3>&- 4>&-
  rm /session-tmp/ui-in /session-tmp/ui-out
  if [ -e /session-data/initial.rgba ]; then rm /session-data/initial.rgba; fi
  if [ -e /session-data/changed.rgba ]; then rm /session-data/changed.rgba; fi
  test -z "$(ls -A /session-data)" || exit 89
  test -z "$(ls -A /session-tmp)" || exit 89
  printf 'UI_CLEANUP=files-removed,child-reaped\n'
  exit 0
fi
"""


def sample_output(case: str, token: str) -> str:
    """Simulated Docker transcript for policy regressions, not runtime evidence."""
    out = f"UI_SESSION={token}\n"
    if case not in {"ui-early", "ui-stale"}:
        out += f"UI_INITIAL={frame_bytes(2).hex()}\n"
        event = {"ui-normal": "RIGHT", "ui-wrong": "WRONG", "ui-missing": "none"}[case]
        out += f"UI_INPUT={event}\n"
    out += f"UI_EXIT={CASES[case]}\n"
    if case == "ui-normal":
        out += f"UI_CHANGED={frame_bytes(3).hex()}\nUI_EVENT=cursor:2->3\n"
    else:
        out += "UI_EVENT=rejected\n"
    return out + "UI_CLEANUP=files-removed,child-reaped\n"


def parse_execution_output(output: str, case: str, token: str) -> dict[str, Any]:
    """Require exact grammar/order and independently check both observed byte arrays."""
    if case not in CASES or not re.fullmatch(r"[0-9a-f]{32}", token):
        raise ValueError("invalid synthetic UI context")
    if not output.isascii() or len(output) > 3072 or output != sample_output(case, token):
        raise ValueError("synthetic UI observation mismatch")
    # Exact byte equality above validates dimensions, length and every pixel.
    frames = {}
    for name in ("initial", "changed"):
        match = re.search(rf"(?m)^UI_{name.upper()}=([0-9a-f]+)$", output)
        if match:
            observed = bytes.fromhex(match[1])
            frames[name] = {**GEOMETRY, "sha256": hashlib.sha256(observed).hexdigest()}
    return {
        "status": "passed",
        "case": case,
        "session_identity": token,
        "frames": frames,
        "guest_exit_code": CASES[case],
        "event": "cursor:2->3" if case == "ui-normal" else "rejected",
        "child_reaped": True,
        "files_removed": True,
    }


def validate_receipt(receipt: Any) -> None:
    """Validate unauthenticated evidence; fixed values require strict JSON types."""
    if not isinstance(receipt, dict):
        raise ValueError("invalid synthetic UI receipt")
    fixed = {
        "schema_version": SCHEMA_VERSION,
        "status": "passed",
        "authenticated": False,
        "scope": "first-party synthetic only; stock M1-04 NOT RUN",
        "input": {"fixture": "RIGHT", "bytes": 6, "sha256": hashlib.sha256(INPUT).hexdigest()},
        "source_sha256": GUEST_SOURCE_SHA256,
        "geometry": GEOMETRY,
    }
    if set(receipt) != {*fixed, "guest_elf_sha256", "qemu_sha256", "sessions"}:
        raise ValueError("incomplete synthetic UI receipt")
    for key, value in fixed.items():
        if json.dumps(receipt[key], sort_keys=True) != json.dumps(value, sort_keys=True):
            raise ValueError("contradictory synthetic UI identity")
    from .synthetic_runtime import QEMU_SHA256

    if receipt["qemu_sha256"] != QEMU_SHA256:
        raise ValueError("unreviewed QEMU identity")
    if not isinstance(receipt["guest_elf_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", receipt["guest_elf_sha256"]
    ):
        raise ValueError("missing guest identity")
    sessions = receipt["sessions"]
    cases = ["ui-normal", "ui-normal", "ui-wrong", "ui-missing", "ui-early", "ui-stale"]
    if not isinstance(sessions, list) or len(sessions) != len(cases):
        raise ValueError("incomplete synthetic UI journey")
    tokens = set()
    for session, case in zip(sessions, cases, strict=True):
        if not isinstance(session, dict) or set(session) != {"observation", "isolation", "cleanup"}:
            raise ValueError("invalid synthetic UI session")
        observation = session["observation"]
        token = observation.get("session_identity") if isinstance(observation, dict) else None
        if (
            not isinstance(token, str)
            or not re.fullmatch(r"[0-9a-f]{32}", token)
            or token in tokens
        ):
            raise ValueError("stale synthetic UI session")
        tokens.add(token)
        expected = parse_execution_output(sample_output(case, token), case, token)
        if json.dumps(observation, sort_keys=True) != json.dumps(expected, sort_keys=True):
            raise ValueError("contradictory frame observation")
        from .synthetic_runtime import _isolation_profile

        expected_isolation = _isolation_profile()
        expected_isolation["stdout_limit_bytes"] = 3072
        if json.dumps(session["isolation"], sort_keys=True) != json.dumps(
            expected_isolation, sort_keys=True
        ):
            raise ValueError("unsafe or contradictory synthetic UI isolation")
        cleanup = session["cleanup"]
        expected_cleanup = {
            "container_removed": True,
            "container_stopped": True,
            "ownership_verified_before_removal": True,
            "container_stop_command": "not-needed",
            "private_tmpfs_released": True,
            "host_metadata": "retained; no recursive cleanup",
        }
        if (
            not isinstance(cleanup, dict)
            or set(cleanup) != set(expected_cleanup)
            or any(
                type(cleanup[key]) is not type(expected) or cleanup[key] != expected
                for key, expected in expected_cleanup.items()
            )
        ):
            raise ValueError("invalid or contradictory synthetic UI cleanup")


def acceptance(inputs: Path, evidence: dict[str, Any], store: Path) -> dict[str, Any]:
    from .synthetic_runtime import launch

    sessions = []
    for index, case in enumerate(
        ("ui-normal", "ui-normal", "ui-wrong", "ui-missing", "ui-early", "ui-stale")
    ):
        session = launch(inputs, evidence, store, session_id=f"ui-{index}", _case=case)
        sessions.append(
            {
                "observation": session["execution"]["ui"],
                "isolation": session["isolation"],
                "cleanup": session["cleanup"],
            }
        )
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "status": "passed",
        "authenticated": False,
        "scope": "first-party synthetic only; stock M1-04 NOT RUN",
        "input": {
            "fixture": "RIGHT",
            "bytes": len(INPUT),
            "sha256": hashlib.sha256(INPUT).hexdigest(),
        },
        "source_sha256": GUEST_SOURCE_SHA256,
        "guest_elf_sha256": evidence["synthetic_ui_guest"]["elf"]["sha256"],
        "qemu_sha256": next(
            a["sha256"] for a in evidence["artifacts"] if a["name"] == "qemu-mipsel"
        ),
        "geometry": GEOMETRY,
        "sessions": sessions,
    }
    validate_receipt(receipt)
    with (store / "synthetic-ui-acceptance.json").open("x", encoding="ascii") as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write("\n")
    return receipt


def parse_receipt(data: bytes) -> dict[str, Any]:
    """Parse portable evidence without granting authenticity or launch authority."""
    if not isinstance(data, bytes) or len(data) > 128 * 1024:
        raise ValueError("synthetic UI receipt exceeds bound")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate synthetic UI evidence key")
            result[key] = value
        return result

    try:
        receipt = json.loads(data, object_pairs_hook=unique)
        validate_receipt(receipt)
    except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
        raise ValueError("invalid synthetic UI evidence") from exc
    return receipt
