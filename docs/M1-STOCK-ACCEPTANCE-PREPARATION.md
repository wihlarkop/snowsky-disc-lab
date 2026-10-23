# M1-05 / M1-06 / M1-08 stock acceptance preparation

Assessment: 2026-10-24, Asia/Jakarta. Base: `15277ad12f85e6d297d93261d23d20d6055f3a64`.
**Stock V2.57 execution remains NOT RUN / UNVERIFIED.** M1-04 through M1-08
remain open. This change supplies executable first-party fixtures and pure
comparators; it supplies no stock launcher or extraction/runtime authorization.

Read with [ROADMAP](ROADMAP.md), [compatibility](COMPATIBILITY.md),
[trust boundaries](TRUST-BOUNDARIES.md), [runtime preparation](M1-01-RUNTIME-PREPARATION.md),
[extraction readiness](M1-EXTRACTION-TOOLCHAIN-READINESS.md),
[Windows/WSL2 evidence](M1-07-WINDOWS-WSL2-VALIDATION.md) and the
[external UI lifecycle ADR](adr/0001-external-ui-handoff.md).
The existing QEMU synthetic runtime and six-session UI acceptance are reused as
regression coverage, with no changes to their commands, guests or receipts.

## Executable foundation

`stock_fixtures.py` generates a half-second first-party stereo ramp track in
memory. It uses integer arithmetic, two unequal channels, signed 16-bit
little-endian interleaved PCM, 48,000 frames/second, 24,000 frames, 48,000 samples
and 96,000 PCM bytes. A frame contains one sample from each channel. RIFF/WAVE
contains the same complete PCM bytes without timestamps or proprietary content.

| Identity | SHA-256 |
| --- | --- |
| Complete raw PCM | `cc38b3a20386adda4cb1369b67d4b70a64d2fa74dffc2ba263851dd9b3a9f0fe` |
| Complete generated WAV | `e3b36f08b99a78c49daee36aabf58408368a09efae53552659f67f670310b192` |

`compare_pcm` requires the selected generated-media identity and format to agree,
checks the complete length and both channels for silence, and compares every
byte. There is no automatic alignment, trimming, resampling, gain adjustment,
prefix-only acceptance or numeric tolerance. A WAV header passed as PCM fails.
A later runner must capture the exact format and complete short track before
calling it. If the stock path produces another format, that is a measured gap to
review; this preparation must not normalize it into an apparent match.

`stock_acceptance.py` defines four ordered logical scenarios:

| Sequence | Scenario | Fixed event payload | Observable response |
| --- | --- | --- | --- |
| 1 | touch-hold | down at (60,180); up after 200 ms | highlight frame |
| 2 | tap-center | down at (180,180); up after 40 ms | selection frame |
| 3 | swipe-left | (300,180) → (240,180) → (120,180) → (60,180), 180 ms | next-page frame |
| 4 | physical-play | play-key down/up, 40 ms | play-state frame |

`input_payload(index)` returns canonical ASCII JSON with exact event ordering
and relative millisecond offsets. These are **logical events, not vendor input
bytes or a verified key mapping**. Each expected response requires a separately
pinned full-frame golden, deadline and payload identity. There is deliberately no
invented stock golden. `compare_inputs` rejects missing/reordered responses,
wrong context/session/payload, non-increasing generations, exceeded deadlines,
wrong frame geometry/identity, missing captured bytes and incorrect full-frame
hashes. The initial format is tightly scoped to 360×360 RGBA8888, stride 1,440,
518,400 bytes. A future adapter must prove the real format and buffer/flush
mapping or version the contract; this assumption is not a hardware claim.

`compare_lifecycle` checks three ordered sessions: cold-clean, restart-persistent,
and restart-clean. Expectations include externally registered session IDs and
per-role PID plus unpredictable process-start handle, pinned readiness frame and
player acknowledgment, boot/stop/restart deadlines, and clean/persistent state
hashes. Observations must match that registration, own both `mq_ui`/`mq_player`,
record normal exit and reaping, and report ownership checks, IPC removal, volatile
state removal and resource release. Stale handles, overlapping restarts,
contradictory state and incomplete teardown fail. Persistent state is explicitly
retained between the first two sessions; the third must begin from the clean
state. This comparator does not inspect PIDs, signal a process, delete files or
prove actual cleanup. The eventual trusted runner must collect those facts.

`compare_media` binds generated WAV import/index identity, complete PCM and
capture timing to the expected ready lifecycle session. Report validation also
requires input responses and media capture to fall between UI readiness and stop,
with exact firmware/runner context equality. All times use one run-relative
monotonic millisecond clock; guest timestamps or wall clocks are not substitutes.
Frame generations must come from reviewed instrumentation, not a polling counter.

## Preparation report contract

The checked-in schema is
`schemas/lab-stock-acceptance-preparation-v1.schema.json`, generated from
`StockReport`. `parse_report(bytes)` accepts at most 128 KiB, rejects duplicate
fields recursively, unknown fields, malformed identities and incomplete or
contradictory evidence, and returns sanitized refusal messages. Strict model
validation rejects booleans/floats in fixed integer fields and integers in fixed
boolean fields. Model instances are revalidated, including nested mutable data.
The JSON Schema describes structure; cross-field identities, lifecycle windows,
full-track counts, scenario digest and other semantic checks require the Python
model/parser. JSON Schema validation alone does not accept an evidence report.

The exact identity tuple has explicit package, original rootfs image, runtime
rootfs overlay inventory, original stock UI/player, runtime player, runner source,
runner binary/patch, shim inventory, runtime image and sanitized host/toolchain
inventory SHA-256 fields. `package` means the SHA-256 of the complete original
owner-supplied ZIP bytes. It is not the intake receipt's sorted-inventory
`package_sha256`; those two identities must never be substituted.
Inventory digests must identify complete canonical
inventories; they must not be substituted with one unspecified shim or a mutable
tag. Unknowns are null with `unmeasured` provenance. Supplied values remain
`declared-unverified`; a digest establishes identity, not vendor authenticity.
The scenario digest binds the entire expected media/input/lifecycle/ownership
contract. Keep proprietary package/binary hashes and private observations local
until the owner separately reviews any export.

Reports contain expected versus observed frames, PCM counts/hashes, import/index,
input timing, process exits, readiness/stop/restart deadlines and cleanup. Portable
metadata cannot prove that captured bytes or host processes existed. The byte
comparators rehash actual bytes supplied by their caller, but the receipt is not
cryptographically authenticated and does not independently establish provenance.
The complete test journey uses fabricated first-party frames, process records and
identities with explicit `simulated-contract-test` basis; it is not stock evidence.

Every report keeps `stock_execution=NOT RUN`, `support_status=unknown`,
`verified=false`, `authenticated=false`, `launch_authorized=false` and
`vendor_authenticity=UNVERIFIED`. Its status can only be NOT RUN, BLOCKED or
UNVERIFIED. Even a complete simulated comparison cannot create stock PASS or a
verified compatibility record. No compatibility registry reader/writer is added.
A future separately reviewed stock-execution report must use a new version;
this preparation schema must retain its present meaning.

## Firmware-free usage and verification

From a clean checkout, the following example generates only synthetic bytes and
a truthful preparation report in memory:

```python
from snowsky_disc_lab.stock_fixtures import (
    FORMAT,
    compare_pcm,
    media_identity,
    pcm_fixture,
    wav_fixture,
)
from snowsky_disc_lab.stock_acceptance import parse_report, preparation_report

wav_bytes = wav_fixture()
pcm_result = compare_pcm(pcm_fixture(), FORMAT, media_identity())
report = preparation_report("a" * 32)  # example ID only; real runs need fresh IDs
assert parse_report(report.model_dump_json().encode()).stock_execution == "NOT RUN"
```

To reproduce focused contract acceptance, with no Docker, QEMU or firmware:

```powershell
uv sync --locked --dev
New-Item -ItemType Directory -Path .lab -Force | Out-Null
uv run --locked pytest tests/test_stock_acceptance.py --basetemp=.lab/stock-contract-tests
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked ty check
```

Local Python 3.14 freethreaded verification passed **89 focused tests**. These
include wrong PCM digest/length/format, silence in either channel, truncated and
partially rendered tracks, incorrect frames, missing responses, stale tokens,
conflicting identities, false PASS/promotion, incomplete evidence and cleanup,
wrong readiness/process ownership, duplicate/malformed JSON, model revalidation
and checked-in schema parity. The parent independently ran the same 89 tests.
The relevant existing M0/M1 intake, contracts, synthetic filesystem/UI/IPC,
supervision, QEMU build and V2.57 boundary regressions passed **360 tests with
3 platform skips**. These are firmware-free policy/contract tests; no new QEMU
execution or Windows stock acceptance is inferred. Hosted exact-head CI is
reported in the Draft PR and must finish before integration.

An initial full-suite attempt used a nested pytest scratch parent that did not
exist (focused tests use no `tmp_path` and had not created it). It produced setup
errors, not a passing run. The full rerun explicitly creates the ignored `.lab`
parent first and passed **819 tests with 4 platform skips** (145.17 seconds).
The run reported existing CLI deprecation and duplicate-ZIP-fixture warnings.
Ruff lint/format, locked Astral ty, schema/model parity and diff checks passed.
No existing scratch or owner files are deleted by these commands.

## Remaining M1 admission work

| Gate | This preparation wave |
| --- | --- |
| Generated full-track WAV/PCM and exact comparator | Firmware-free tests PASS |
| Ordered logical inputs, response/frame/deadline comparator | Firmware-free tests PASS; real adapter/goldens UNVERIFIED |
| Externally bound readiness/process/state/cleanup comparator | Firmware-free tests PASS; actual lifecycle NOT RUN |
| Strict versioned evidence model/schema | Firmware-free tests PASS; no stock promotion possible |
| Package authenticity, authorized reproducible extraction, measured original/rootfs/ELF identities | BLOCKED pending separate intake/trust gates |
| Trusted isolated runtime and measured runner/shim/overlay tuple | UNVERIFIED for stock execution |
| Actual stock input mapping, framebuffer generation/capture and trusted frame goldens | NOT RUN |
| Real generated-media SD import/index and full-track stock PCM capture | NOT RUN |
| Actual stop/restart/persistent-state isolation/cleanup | NOT RUN |
| Windows/WSL2 stock runtime acceptance and hardware fidelity | NOT RUN / UNVERIFIED |

Next work must pin a reviewed input adapter, actual framebuffer/PCM capture
instrumentation and independently reviewed golden artifacts for the exact
stock/runtime tuple. Existing synthetic frame or audio fixtures must never be
substituted for these missing observations. Keep M1-05/M1-06/M1-08 open until
separately authorized stock acceptance actually occurs. No stock firmware is run
automatically when this preparation or another preflight check passes.
