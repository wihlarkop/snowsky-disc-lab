"""Deterministic first-party media and complete-byte comparisons; no runtime IO."""

from __future__ import annotations

import hashlib
import io
import struct
import wave
from functools import cache
from typing import Annotated, Any, Literal, get_args, get_origin

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Sha256 = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$")]
Count = Annotated[int, Field(strict=True, ge=0, le=2**53 - 1)]


class Contract(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, revalidate_instances="always"
    )

    @model_validator(mode="before")
    @classmethod
    def strict_literals(cls, value: Any) -> Any:
        # Literal[True] otherwise accepts 1; Literal[2] accepts 2.0/bools.
        if isinstance(value, cls):
            value = value.model_dump(warnings="none")
        if isinstance(value, dict):
            for name, field in cls.model_fields.items():
                if name in value and get_origin(field.annotation) is Literal:
                    types = {type(item) for item in get_args(field.annotation)}
                    if type(value[name]) not in types:
                        raise ValueError("literal type mismatch")
        return value


class PCMFormat(Contract):
    encoding: Literal["signed-integer-little-endian"]
    sample_rate: Annotated[int, Field(strict=True, ge=1, le=192000)]
    channels: Annotated[int, Field(strict=True, ge=1, le=8)]
    sample_width_bytes: Literal[2]


class MediaIdentity(Contract):
    fixture_id: Literal["lab-stereo-ramp-v1"]
    format: PCMFormat
    frame_count: Count
    sample_count: Count
    pcm_bytes: Count
    pcm_sha256: Sha256
    wav_sha256: Sha256


FORMAT = PCMFormat(
    encoding="signed-integer-little-endian", sample_rate=48000, channels=2, sample_width_bytes=2
)
FRAME_COUNT = 24000


@cache
def pcm_fixture() -> bytes:
    """Half a second of unequal non-silent stereo integer ramps, no float math."""
    return b"".join(
        struct.pack("<hh", ((i * 257) % 24001) - 12000, ((i * 509 + 71) % 20001) - 10000)
        for i in range(FRAME_COUNT)
    )


@cache
def wav_fixture() -> bytes:
    """Canonical uncompressed RIFF/WAVE generated entirely in memory."""
    output = io.BytesIO()
    with wave.open(output, "wb") as stream:
        stream.setnchannels(FORMAT.channels)
        stream.setsampwidth(FORMAT.sample_width_bytes)
        stream.setframerate(FORMAT.sample_rate)
        stream.writeframes(pcm_fixture())
    return output.getvalue()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def media_identity() -> MediaIdentity:
    pcm = pcm_fixture()
    return MediaIdentity(
        fixture_id="lab-stereo-ramp-v1",
        format=FORMAT,
        frame_count=FRAME_COUNT,
        sample_count=FRAME_COUNT * FORMAT.channels,
        pcm_bytes=len(pcm),
        pcm_sha256=sha256(pcm),
        wav_sha256=sha256(wav_fixture()),
    )


class PCMObservation(Contract):
    """A comparison receipt is a declaration until the actual capture is reviewed."""

    media: MediaIdentity
    captured_format: PCMFormat
    frame_count: Count
    sample_count: Count
    pcm_bytes: Count
    pcm_sha256: Sha256
    all_channels_non_silent: Literal[True]
    comparison: Literal["exact-full-track-bytes"]


def compare_pcm(
    data: bytes, captured_format: PCMFormat, selected_media: MediaIdentity
) -> PCMObservation:
    """Refuse offsets, resampling, gain changes, tolerance, silence and partial tracks.

    Input is raw interleaved signed 16-bit LE PCM, with no WAV header. There is no
    capture/trim/alignment policy: every byte from first through last must match.
    """
    expected = media_identity()
    selected = MediaIdentity.model_validate(selected_media)
    actual_format = PCMFormat.model_validate(captured_format)
    if selected != expected:
        raise ValueError("media identity mismatch")
    if actual_format != FORMAT:
        raise ValueError("PCM format mismatch")
    if not isinstance(data, bytes) or len(data) != expected.pcm_bytes:
        raise ValueError("PCM full-track length mismatch")
    samples = tuple(struct.iter_unpack("<hh", data))
    if any(not any(frame[channel] for frame in samples) for channel in range(2)):
        raise ValueError("silent PCM channel")
    if data != pcm_fixture():
        raise ValueError("PCM sample mismatch")
    return PCMObservation(
        media=selected,
        captured_format=actual_format,
        frame_count=len(samples),
        sample_count=len(samples) * actual_format.channels,
        pcm_bytes=len(data),
        pcm_sha256=sha256(data),
        all_channels_non_silent=True,
        comparison="exact-full-track-bytes",
    )
