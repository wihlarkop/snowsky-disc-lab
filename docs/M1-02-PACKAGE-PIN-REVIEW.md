# M1-02 — Exact V2.57 package pin and manifest self-reference review

**Status: SOURCE-ONLY INVESTIGATION / NOT AN ADMISSION POLICY.** Prepared 2026-10-25 from immutable public source files. No FiiO ZIP, filesystem image, vendor binary, on-device data, private key, decrypted asset or personal music was acquired, read, uploaded, extracted or executed for this review. **M1-02 remains REFUSED for a complete V2.57 ancillary set; M1-03 extraction and M1-04 stock boot remain NOT RUN.**

This is an actionable decision input for [firmware intake](FIRMWARE-INTAKE.md) and [extraction readiness](M1-EXTRACTION-TOOLCHAIN-READINESS.md); it does **not** supersede their existing guards. The goals are to (a) identify separately what an external **whole-ZIP exact-byte pin** proves, (b) avoid inventing a self-hash algorithm, and (c) spell out the evidence needed before a future owner-reviewed change.

## 1. Current block at exact Lab main

- Reviewed base: `b1da7c9ce16b4cca00b9b7655e207861b4797859` (PR #39).
- Current `firmware_intake._inspect_package` verifies bounded ZIP/member structure, V2.57 main/recovery metadata, indexed rootfs members and exact membership/digest of ancillary entries *except* the controlling manifest's self reference. A complete ancillary set explicitly raises `manifest_self_reference_unverifiable`.
- Current `IntakeReceipt` reports `vendor_authenticity=unverified`, and all `may_proceed`, `extraction_authorized`, `execution_authorized` flags remain `false`.
- The main `manifest.sha256` includes `SHA256(ota/manifest.sha256)= <digest>`. No reviewed producer-side canonicalization or signature-verification specification explains the meaning of this embedded value. Hashing the full bytes and demanding this row match is not a practical self-verification rule. Do **not** guess zeroing, exclusion, fixed-point computation, or accept arbitrary replacement values as vendor policy.
- Existing tests deliberately cover the refusal, including a wrong-self-digest synthetic mutation. Any policy change must preserve a strict negative path and must not silently promote a synthetic/unpinned package.

## 2. Independently inspected immutable public-source claims

| Record | Source/commit | Reported identity | Meaning and limit |
| --- | --- | --- | --- |
| Whole official V2.57 ZIP | [diskOS `firmware_catalogue.py`](https://github.com/b0hemia/diskos/blob/66af1f639fd7c4adbb15f5b605100c3fd5733b8a/diskos_installer/firmware_catalogue.py) | Exact length **105,680,009 bytes**, SHA-256 `2bfad000609440bcbf492468e9e5f8f3d5e0bade797323431a15b5755688bfcf` | diskOS's fixed catalogue associates this identity with the official FiiO V2.57 download. This is an **upstream source claim**, not an independently verified vendor signature or our own measurement. |
| Extracted V2.57 rootfs | [diskOS `imagebuild.py`](https://github.com/b0hemia/diskos/blob/66af1f639fd7c4adbb15f5b605100c3fd5733b8a/diskos_installer/imagebuild.py) | **80,596,992 bytes**, SHA-256 `111e4dd7ee3d7ff91ba7e61181690be7ffd22bd1bbd13ad513f5f015ffb302ae` | diskOS states this pin was qualified against a real V2.57 DISC. Do not import its result as Lab physical-device validation. |
| Extracted V2.57 rootfs | [QEMU integration `firmware/v2.57.json`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/firmware/v2.57.json) | **80,596,992 bytes**, SHA-256 `111e4dd7ee3d7ff91ba7e61181690be7ffd22bd1bbd13ad513f5f015ffb302ae`; 77 chunks; main/recovery `257/18` | Independent public repo agrees on rootfs bytes, not a second source for the exact whole-ZIP digest. Shared provenance/derivation between projects has not been ruled out. |
| Main manifest inventory | [QEMU integration `firmware_inventory.py`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/firmware/tools/firmware_inventory.py) | Only checks rootfs-member hashes; reports `manifest_signature_verified: false` | Does **not** establish the self-reference or signature convention. |
| Decryption and unpacking | [diskOS `imagebuild.py`](https://github.com/b0hemia/diskos/blob/66af1f639fd7c4adbb15f5b605100c3fd5733b8a/diskos_installer/imagebuild.py) | Decrypts/reassembles main_os OTA chunks and compares reconstructed rootfs with an out-of-band pinned digest | Its operational pathway is source evidence, **not** permission to run the Lab extractor without local isolation, rights, output checks and owner approval. |

The source records identify concrete candidate reference inputs. They **do not** authenticate the publisher of a whole ZIP by themselves, prove the exact downloaded bytes in the owner's workstation, or establish a vendor public-key chain. A matching hash is byte identity *relative to the chosen reference*, not vendor-origin attestation. The common rootfs digest is useful corroboration but cannot replace a separate trust decision.

## 3. Distinct proofs and possible policy decisions

| Gate | Potential evidence | May it be claimed from source alone? |
| --- | --- | --- |
| Exact archive identity | Independently streamed whole-ZIP `sha256` and byte count from an authorized local owner-selected archive; compare against separately reviewed pinned catalogue bytes | **NO**; external pin is a candidate; local comparison still NOT RUN under this review |
| ZIP boundedness and complete member inventory | Existing Lab inspector and member hashes plus full original archive re-hash | Existing synthetic coverage; actual V2.57 archive still REFUSED |
| Self-referential manifest semantic verification | Reviewed documented vendor checksum/signature convention over specifically identified canonical bytes, with positive/negative synthetic tests | **NO**; unknown |
| Package provenance/authenticity | A validated vendor signature chain **or** a separately approved, narrowly stated owner-provenance policy that clearly labels lack of vendor cryptographic authentication | **NO**; awaiting policy review and authority |
| Plaintext rootfs and stock ELF identities | Dedicated verified extraction output matching 80,596,992 byte rootfs plus reviewed stock player/UI/lib fingerprints | **NO**; extraction not authorized/run |
| Firmware-backed execution | Exact authorized package + verified process isolation + toolchain/rights + QEMU runner + owner permission | **NO**; M1-04 NOT RUN |

**Candidate approach, for review only:** an explicit, **separate** `known-package exact-ZIP match` check against a source-reviewed pin may provide a deterministic *whole-archive byte identity* independent of any self-referential row. For such exact bytes, a semantic self-hash rule may be unnecessary **for the narrow statement that this is the exact pinned ZIP**, but absence of a verified rule **must remain visible**. Whether the Lab may accept such a package for a later stage is a distinct **owner-approved trust-policy** decision, not a parser convenience. Matching any digest supplied *inside* the archive or its own manifest does not establish this proof.

**Do not implement an implicit bypass.** Until a proposal defines the scope, approver, risk, fallback/refusal, verifiable reference provenance and authorization, the current `manifest_self_reference_unverifiable` refusal stays intact. A nonmatching ZIP, unknown input version, malformed member, contradictory manifest, ambiguous root, or unreviewed provenance must still fail closed.

## 4. Next implementation slice: firmware-free and bounded

A separate Codex task can safely do the following **without opening any vendor firmware**:

1. Inventory and cite the exact public sources in section 2 and verify their immutable Git blob/commit identities; inspect current inspector/receipt schema, synthetic ZIP tests, and Lab trust policy.
2. Propose one of **(A)** reviewed self-reference/signature semantics with traceable authoritative evidence, **(B)** an explicitly constrained exact-whole-ZIP pin policy retaining the separate authenticity limitation, or **(C)** continued refusal when neither can be justified. Record an auditable decision request, not a silently changed safety gate.
3. If implementing a **read-only, evidence-only pin check**, source the length/hash from a reviewed first-party static catalog, compare only a fully streamed stable ZIP, never from a digest in the ZIP, and expose the result under an independently versioned evidence contract or a carefully reviewed compatible schema extension. Initially do **not** set `status=accepted` from this check or allow extraction/execution.
4. Write synthetic tests for matching/mismatching known-size/digest, truncate/append, mutated manifest and all ancillary bytes, missing/unrecognized ZIP, directory input (no original ZIP digest), malformed metadata, false vendor-authenticity claims, receipt mutation, and preserved no-process/no-network/no-output behavior.
5. Run repository formatting, lint, typing, focused tests and hosted firmware-free CI. Produce exact-head evidence, a small Draft PR, and an explicit list of unresolved decisions; never write to `upstreams.lock.yaml` just to change candidate approval.

**No authorized real ZIP re-inspection is implied.** A later owner-controlled run requires an explicit, approved, read-only request for the specific file and output redaction; not a Codex agent deciding to retry automatically.

## 5. M1 dependency to genuine completion

1. **M1-02:** Decide and implement documented exact-package provenance/admission semantics; separately validate authorized, owner-supplied V2.57 evidence under a reviewed safe input policy. Do not conflate integrity with vendor signature.
2. **M1-03:** Review/licence-pin extraction toolchain; run a **single nonprivileged, networkless, resource-bounded session inside a dedicated trusted disposable Linux VM** with verified snapshots, quotas, nonreplace output publication and quarantine on any failure. Validate exact rootfs and six original stock ELF hashes.
3. **M1-01 / M1-07:** Preserve reproducible hosted firmware-free QEMU build receipts; separately establish an acceptable *local/controlled* `linux/amd64` isolation boundary, resource availability and cleanup, especially for Windows/WSL2. A 16 GiB Windows host's Docker Engine capacity alone does not establish 8 GiB actual `MemAvailable` or trusted isolation.
4. **M1-04:** With approved exact identities and explicit authority, boot stock `mq_ui` + `mq_player` on the pinned reviewed QEMU runner. **Observed** framebuffer generation, mqueue/process ownership and player readiness are mandatory; no stale/synthetic frame substitutions.
5. **M1-05/06:** Exercise touch/keys, synthetic SD media scan, complete PCM fixtures, pause/seek/queue as applicable, restart/persistence and bounded failure cleanup using stock binaries. Record unsupported hardware behavior instead of emulating success.
6. **M1-08:** Publish a source-safe, provenance-rich acceptance record with exact firmware/UI/player hashes **as permitted**, runner/toolchain/VM fingerprints, commands, test results and known limitations. Do not export vendor binaries or personal tracks. Keep Windows-specific runtime validation and physical-device testing separately labeled.

**Completion definition:** M1 is not fully accepted while any required stock V2.57 runtime scenario or explicitly stated supported Windows path is NOT RUN/BLOCKED. A CI green check, an exact archive pin, or a third-party installer success is not sufficient by itself. Record any scope adjustment explicitly before changing milestone status.
