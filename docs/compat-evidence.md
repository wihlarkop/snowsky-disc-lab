# Compatibility evidence reports

The M5 subset in this release reads sanitized Lab-generated JSON receipts and
produces local JSON or Markdown reports. It accepts
`firmware-free-synthetic-runtime-acceptance/v1`, including the nested
`firmware-free-mips32le-posix-mqueue-acceptance/v1` receipt, or the same
synthetic receipt inside a `firmware-free-qemu-runtime-build/v1` summary.
No other schema versions or receipt sources are accepted.

The parser rejects malformed JSON, duplicate keys, unknown fields, invalid
digests, unknown statuses and contradictory parent/child outcomes. Inputs are
limited to 1 MiB. The report retains the source label, exact artifact hashes,
synthetic source hash, measured synthetic input hash and, for QEMU build
summaries, the upstream repository, commit and projection digest.
The CLI validates the receipt structure and preserves receipt-provided identity
claims. It does not authenticate the receipt's origin or recompute artifact
hashes from binary inputs.

Run a report locally:

```console
disc-lab compat report receipt.json --format markdown
disc-lab compat report receipt-a.json receipt-b.json --format json
```

Scenario results are `PASS`, `FAIL`, `NOT RUN`, `UNSUPPORTED` or `BLOCKED`.
Unrecorded cases remain `NOT RUN`; quarantined sessions are `BLOCKED`; a
sanitized known queue syscall failure is `FAIL`. The explicit
`arbitrary binary isolation` runtime limitation is reported `UNSUPPORTED`.
The fixed synthetic filesystem and queue probes are reported as synthetic
scenarios. `stock-v257-boot` and `stock-ipc-compatibility` remain `NOT RUN` for
these firmware-free receipts. Reports always keep overall support status
`unknown`; they do not promote `verified-emulator`, `verified-device` or any
other support state.

QEMU build receipts are accepted only when their source identity is exact and
their recorded boundaries state that firmware was not processed, the guest
did not boot and compatibility was not claimed. A firmware-free synthetic
execution verifies only its named first-party probes under the recorded
runtime. It does not establish vendor firmware behavior, authenticity,
hardware compatibility, UI compatibility or a stock player protocol.

Only JSON matching the fixed receipt schemas is parsed; receipt provenance is
unverified. Raw logs, binary artifacts and screenshots are not accepted as
inputs. The CLI does not contact a runtime, modify source receipts or infer
missing identities.
