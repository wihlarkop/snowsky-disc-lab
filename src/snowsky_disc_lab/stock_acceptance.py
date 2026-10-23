"""Preparation-only stock acceptance contracts and pure outcome comparators.

No launcher, filesystem reader, compatibility-registry writer or trust promotion.
Portable reports contain unverified declarations, even after byte comparisons.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from pydantic import Field, ValidationError, model_validator

from .stock_fixtures import (
    Contract,
    Count,
    MediaIdentity,
    PCMObservation,
    Sha256,
    media_identity,
    sha256,
)

Identifier = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$", strict=True)]
SessionID = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$", strict=True)]
Deadline = Annotated[int, Field(strict=True, ge=1, le=60000)]
SCHEMA_VERSION = "lab-stock-acceptance-preparation/v1"
MAX_REPORT_BYTES = 128 * 1024

# Logical model only: an eventual reviewed device adapter must map these events.
# Each payload is canonical ASCII JSON; timestamps are relative milliseconds.
INPUTS: tuple[tuple[str, tuple[tuple[int, str, int, int], ...], str], ...] = (
    ("touch-hold", ((0, "touch-down", 60, 180), (200, "touch-up", 60, 180)), "highlight"),
    ("tap-center", ((0, "touch-down", 180, 180), (40, "touch-up", 180, 180)), "selection"),
    (
        "swipe-left",
        (
            (0, "touch-down", 300, 180),
            (60, "touch-move", 240, 180),
            (120, "touch-move", 120, 180),
            (180, "touch-up", 60, 180),
        ),
        "next-page",
    ),
    ("physical-play", ((0, "key-play-down", 0, 0), (40, "key-play-up", 0, 0)), "play-state"),
)


def input_payload(index: int) -> bytes:
    if type(index) is not int or not 0 <= index < len(INPUTS):
        raise ValueError("unknown input step")
    return json.dumps(INPUTS[index][1], separators=(",", ":")).encode("ascii")


class ArtifactIdentity(Contract):
    sha256: Sha256 | None
    provenance: Literal["unmeasured", "declared-unverified"]

    @model_validator(mode="after")
    def consistent(self) -> ArtifactIdentity:
        if (self.sha256 is None) != (self.provenance == "unmeasured"):
            raise ValueError("contradictory artifact provenance")
        return self


class Identities(Contract):
    """Exact tuple, with unknowns explicit and no aliases across original/overlay."""

    firmware_version: Literal["2.57"]
    package: ArtifactIdentity  # Complete original ZIP bytes, never an intake inventory digest.
    rootfs_image: ArtifactIdentity
    rootfs_overlay: ArtifactIdentity
    original_mq_ui: ArtifactIdentity
    original_mq_player: ArtifactIdentity
    runtime_mq_player: ArtifactIdentity
    runner_source: ArtifactIdentity
    runner_binary: ArtifactIdentity
    runner_patch: ArtifactIdentity
    shims: ArtifactIdentity  # Canonical inventory digest, not one unspecified .so.
    runtime_image: ArtifactIdentity
    host: ArtifactIdentity  # Sanitized, reviewed host/toolchain inventory digest.

    def complete(self) -> bool:
        return all(
            isinstance(value, dict) and value.get("sha256") is not None
            for key, value in self.model_dump().items()
            if key != "firmware_version"
        )


class Context(Contract):
    run_id: SessionID
    identities: Identities


class Frame(Contract):
    width: Literal[360]
    height: Literal[360]
    stride_bytes: Literal[1440]
    pixel_format: Literal["RGBA8888"]
    bytes: Literal[518400]
    sha256: Sha256


class InputExpectation(Contract):
    step_id: Identifier
    sequence: Annotated[int, Field(strict=True, ge=1, le=4)]
    payload_sha256: Sha256
    response: Identifier
    deadline_ms: Deadline
    frame: Frame


class InputPlan(Contract):
    steps: Annotated[list[InputExpectation], Field(min_length=4, max_length=4)]

    @model_validator(mode="after")
    def fixed_order(self) -> InputPlan:
        for index, step in enumerate(self.steps):
            if (
                (step.step_id, step.response) != (INPUTS[index][0], INPUTS[index][2])
                or step.sequence != index + 1
                or step.payload_sha256 != sha256(input_payload(index))
            ):
                raise ValueError("input identity or order mismatch")
        return self


class InputObservation(Contract):
    context: Context
    session_id: SessionID
    step_id: Identifier
    sequence: Count
    payload_sha256: Sha256
    response: Identifier
    sent_ms: Count
    observed_ms: Count
    generation: Count
    frame: Frame


def _check_inputs(
    context: Context, session_id: str, plan: InputPlan, observations: list[InputObservation]
) -> None:
    if len(observations) != len(plan.steps):
        raise ValueError("missing input response")
    previous_ms = -1
    previous_generation = 0
    for expected, observed in zip(plan.steps, observations, strict=True):
        if observed.context != context or observed.session_id != session_id:
            raise ValueError("stale session or conflicting identity")
        if (
            observed.step_id != expected.step_id
            or observed.sequence != expected.sequence
            or observed.payload_sha256 != expected.payload_sha256
            or observed.response != expected.response
            or observed.frame != expected.frame
        ):
            raise ValueError("input response or frame identity mismatch")
        if (
            observed.sent_ms <= previous_ms
            or observed.observed_ms < observed.sent_ms
            or observed.observed_ms - observed.sent_ms > expected.deadline_ms
            or observed.generation <= previous_generation
        ):
            raise ValueError("input ordering, generation or deadline mismatch")
        previous_ms = observed.observed_ms
        previous_generation = observed.generation


def compare_inputs(
    context: Context,
    session_id: str,
    plan: InputPlan,
    observations: list[InputObservation],
    captured_frames: list[bytes],
) -> list[InputObservation]:
    """Revalidate declarations and hash complete observed frames, never log strings."""
    context = Context.model_validate(context)
    plan = InputPlan.model_validate(plan)
    observations = [InputObservation.model_validate(item) for item in observations]
    _check_inputs(context, session_id, plan, observations)
    if len(captured_frames) != len(plan.steps):
        raise ValueError("missing captured frame")
    for expected, observed, data in zip(plan.steps, observations, captured_frames, strict=True):
        if (
            not isinstance(data, bytes)
            or len(data) != expected.frame.bytes
            or sha256(data) != expected.frame.sha256
            or sha256(data) != observed.frame.sha256
        ):
            raise ValueError("captured frame mismatch")
    return observations


class ProcessOwner(Contract):
    role: Literal["mq_ui", "mq_player"]
    pid: Annotated[int, Field(strict=True, ge=1, le=2**31 - 1)]
    start_identity: SessionID  # Opaque runner start handle; PID alone is insufficient.


class Process(ProcessOwner):
    session_id: SessionID
    owner_run_id: SessionID
    exit_code: Annotated[int, Field(strict=True, ge=-255, le=255)]
    reaped: bool


class SessionOwner(Contract):
    session_id: SessionID
    processes: Annotated[list[ProcessOwner], Field(min_length=2, max_length=2)]


class LifecycleExpectation(Contract):
    ownership: Annotated[list[SessionOwner], Field(min_length=3, max_length=3)]
    readiness_frame: Frame
    readiness_player_ack_sha256: Sha256
    boot_deadline_ms: Deadline
    stop_deadline_ms: Deadline
    restart_deadline_ms: Deadline
    initial_state_sha256: Sha256
    persistent_state_sha256: Sha256


class Session(Contract):
    context: Context
    session_id: SessionID
    mode: Literal["cold-clean", "restart-persistent", "restart-clean"]
    previous_session_id: SessionID | None
    started_ms: Count
    player_ready_ms: Count
    ui_ready_ms: Count
    stop_requested_ms: Count
    stopped_ms: Count
    readiness_session_id: SessionID
    readiness_frame: Frame
    readiness_player_ack_sha256: Sha256
    initial_state_sha256: Sha256
    final_state_sha256: Sha256
    processes: Annotated[list[Process], Field(min_length=2, max_length=2)]
    ownership_checked: bool
    ipc_removed: bool
    volatile_state_removed: bool
    resources_released: bool


class LifecycleObservation(Contract):
    sessions: Annotated[list[Session], Field(min_length=3, max_length=3)]


def compare_lifecycle(
    context: Context, expected: LifecycleExpectation, observed: LifecycleObservation
) -> LifecycleObservation:
    """Validate a cold boot, persistent restart, clean restart and all owned stops.

    This consumes declarations; it neither checks host PIDs nor cleans resources.
    Future instrumentation must collect them in the trusted runtime boundary.
    """
    context = Context.model_validate(context)
    expected = LifecycleExpectation.model_validate(expected)
    observed = LifecycleObservation.model_validate(observed)
    tokens: set[str] = set()
    handles: set[str] = set()
    previous: Session | None = None
    for session, mode, owner in zip(
        observed.sessions,
        ("cold-clean", "restart-persistent", "restart-clean"),
        expected.ownership,
        strict=True,
    ):
        if (
            session.context != context
            or session.session_id != owner.session_id
            or session.readiness_frame != expected.readiness_frame
            or session.readiness_player_ack_sha256 != expected.readiness_player_ack_sha256
            or session.mode != mode
            or session.session_id in tokens
            or session.readiness_session_id != session.session_id
            or session.previous_session_id != (previous.session_id if previous else None)
        ):
            raise ValueError("stale lifecycle session or conflicting identity")
        tokens.add(session.session_id)
        if not (
            session.started_ms
            <= session.player_ready_ms
            <= session.ui_ready_ms
            <= session.stop_requested_ms
            <= session.stopped_ms
        ):
            raise ValueError("lifecycle event order mismatch")
        if (
            session.ui_ready_ms - session.started_ms > expected.boot_deadline_ms
            or session.stopped_ms - session.stop_requested_ms > expected.stop_deadline_ms
            or (
                previous
                and (
                    session.started_ms < previous.stopped_ms
                    or session.ui_ready_ms - previous.stopped_ms > expected.restart_deadline_ms
                )
            )
        ):
            raise ValueError("lifecycle deadline exceeded")
        initial = (
            expected.persistent_state_sha256
            if mode == "restart-persistent"
            else expected.initial_state_sha256
        )
        if (
            session.initial_state_sha256 != initial
            or session.final_state_sha256 != expected.persistent_state_sha256
        ):
            raise ValueError("clean or persistent state mismatch")
        if {process.role for process in session.processes} != {"mq_ui", "mq_player"}:
            raise ValueError("missing or duplicate owned process")
        if len({process.pid for process in session.processes}) != 2:
            raise ValueError("conflicting process identity")
        if {process.role for process in owner.processes} != {"mq_ui", "mq_player"}:
            raise ValueError("incomplete expected ownership")
        owners = {process.role: process for process in owner.processes}
        for process in session.processes:
            registered = owners[process.role]
            if (
                (process.pid, process.start_identity) != (registered.pid, registered.start_identity)
                or process.session_id != session.session_id
                or process.owner_run_id != context.run_id
                or process.start_identity in handles
                or process.exit_code != 0
                or not process.reaped
            ):
                raise ValueError("process ownership, exit or reaping mismatch")
            handles.add(process.start_identity)
        if not all(
            (
                session.ownership_checked,
                session.ipc_removed,
                session.volatile_state_removed,
                session.resources_released,
            )
        ):
            raise ValueError("incomplete owned teardown")
        previous = session
    return observed


class Expected(Contract):
    media: MediaIdentity
    media_deadline_ms: Deadline
    inputs: InputPlan | None
    lifecycle: LifecycleExpectation | None


class MediaObservation(Contract):
    context: Context
    session_id: SessionID
    imported_ms: Count
    indexed_ms: Count
    capture_started_ms: Count
    capture_ended_ms: Count
    imported_wav_sha256: Sha256
    indexed_media_sha256: Annotated[list[Sha256], Field(min_length=1, max_length=1)]
    pcm: PCMObservation


def _check_media(
    context: Context, expected: Expected, media: MediaObservation, session: Session
) -> None:
    if (
        media.context != context
        or media.session_id != session.session_id
        or media.imported_wav_sha256 != expected.media.wav_sha256
        or media.indexed_media_sha256 != [expected.media.wav_sha256]
    ):
        raise ValueError("media index identity or session mismatch")
    if (
        not (
            session.ui_ready_ms
            <= media.imported_ms
            <= media.indexed_ms
            <= media.capture_started_ms
            <= media.capture_ended_ms
            <= session.stop_requested_ms
        )
        or media.capture_ended_ms - media.imported_ms > expected.media_deadline_ms
    ):
        raise ValueError("media capture outside session or deadline")
    pcm = media.pcm
    if (
        pcm.media != expected.media
        or pcm.captured_format != expected.media.format
        or pcm.frame_count != expected.media.frame_count
        or pcm.sample_count != expected.media.sample_count
        or pcm.pcm_bytes != expected.media.pcm_bytes
        or pcm.pcm_sha256 != expected.media.pcm_sha256
    ):
        raise ValueError("contradictory PCM evidence")


def compare_media(
    context: Context, expected: Expected, media: MediaObservation, session: Session, data: bytes
) -> MediaObservation:
    """Bind index and complete PCM bytes to the expected media and ready session."""
    from .stock_fixtures import compare_pcm

    context = Context.model_validate(context)
    expected = Expected.model_validate(expected)
    media = MediaObservation.model_validate(media)
    session = Session.model_validate(session)
    if expected.media != media_identity() or session.context != context:
        raise ValueError("media expectation or session context mismatch")
    _check_media(context, expected, media, session)
    if compare_pcm(data, media.pcm.captured_format, expected.media) != media.pcm:
        raise ValueError("PCM comparison receipt mismatch")
    return media


class Observed(Contract):
    context: Context
    input_session_id: SessionID
    inputs: Annotated[list[InputObservation], Field(min_length=4, max_length=4)]
    media: MediaObservation
    lifecycle: LifecycleObservation
    basis: Literal["simulated-contract-test", "operator-declared-unverified"]


class StockReport(Contract):
    """A preparation report can never establish stock PASS or compatibility."""

    schema_version: Literal["lab-stock-acceptance-preparation/v1"]
    status: Literal["NOT RUN", "BLOCKED", "UNVERIFIED"]
    stock_execution: Literal["NOT RUN"]
    support_status: Literal["unknown"]
    verified: Literal[False]
    authenticated: Literal[False]
    launch_authorized: Literal[False]
    vendor_authenticity: Literal["UNVERIFIED"]
    context: Context
    scenario_sha256: Sha256
    expected: Expected
    observed: Observed | None
    limitations: Literal[
        "Preparation only; declarations are unauthenticated. No stock execution, hardware "
        "framebuffer/audio fidelity, vendor authenticity or compatibility is established."
    ]

    @model_validator(mode="after")
    def honest_evidence(self) -> StockReport:
        if self.expected.media != media_identity():
            raise ValueError("unexpected media identity")
        if self.scenario_sha256 != scenario_digest(self.expected):
            raise ValueError("conflicting scenario identity")
        if self.observed is None:
            return self
        observed = self.observed
        if (
            self.status != "UNVERIFIED"
            or observed.context != self.context
            or not self.context.identities.complete()
            or self.expected.inputs is None
            or self.expected.lifecycle is None
        ):
            raise ValueError("incomplete evidence or conflicting identity")
        _check_inputs(
            self.context, observed.input_session_id, self.expected.inputs, observed.inputs
        )
        compare_lifecycle(self.context, self.expected.lifecycle, observed.lifecycle)
        if observed.input_session_id != observed.lifecycle.sessions[0].session_id:
            raise ValueError("input session does not belong to lifecycle")
        first = observed.lifecycle.sessions[0]
        if (
            observed.inputs[0].sent_ms < first.ui_ready_ms
            or observed.inputs[-1].observed_ms > first.stop_requested_ms
        ):
            raise ValueError("input outside ready session lifetime")
        _check_media(self.context, self.expected, observed.media, first)
        return self


def scenario_digest(expected: Expected) -> str:
    return sha256(json.dumps(expected.model_dump(), sort_keys=True, separators=(",", ":")).encode())


def preparation_report(run_id: str) -> StockReport:
    """Truthful empty report; never invent firmware, host or frame identities."""
    unknown = {"sha256": None, "provenance": "unmeasured"}
    identities = Identities.model_validate(
        {
            "firmware_version": "2.57",
            **{key: unknown for key in Identities.model_fields if key != "firmware_version"},
        }
    )
    expected = Expected(media=media_identity(), media_deadline_ms=5000, inputs=None, lifecycle=None)
    return StockReport(
        schema_version=SCHEMA_VERSION,
        status="BLOCKED",
        stock_execution="NOT RUN",
        support_status="unknown",
        verified=False,
        authenticated=False,
        launch_authorized=False,
        vendor_authenticity="UNVERIFIED",
        context=Context(run_id=run_id, identities=identities),
        scenario_sha256=scenario_digest(expected),
        expected=expected,
        observed=None,
        limitations=(
            "Preparation only; declarations are unauthenticated. No stock execution, hardware "
            "framebuffer/audio fidelity, vendor authenticity or compatibility is established."
        ),
    )


def parse_report(data: bytes) -> StockReport:
    """Bounded strict JSON, duplicate keys rejected recursively, sanitized errors."""
    if not isinstance(data, bytes) or len(data) > MAX_REPORT_BYTES:
        raise ValueError("invalid stock preparation report")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        values: dict[str, Any] = {}
        for key, value in pairs:
            if key in values:
                raise ValueError("duplicate receipt field")
            values[key] = value
        return values

    try:
        document = json.loads(data, object_pairs_hook=unique)
        return StockReport.model_validate(document)
    except (ValueError, ValidationError, TypeError, RecursionError, UnicodeError):
        raise ValueError("invalid stock preparation report") from None
