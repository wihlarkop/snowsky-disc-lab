# M1-02 — offline firmware intake foundation

`disc-lab firmware inspect PATH` inspects a locally selected ZIP or unpacked package directory. It reads bounded streams and emits a structural inspection receipt. ZIP decompression happens only in memory while hashing members; no member is extracted to disk. Firmware decryption, plaintext reconstruction, mounting, patching and execution are absent. Development and verification use generated synthetic samples only.

```sh
uv run disc-lab firmware inspect /local/private/candidate.zip
uv run disc-lab firmware inspect /local/private/package --format json
```

The default format is text; `--format json` emits only a `lab-firmware-intake/v1` JSON receipt on stdout. Exit 0 means **structurally accepted under this policy**, and exit 2 means refused. The existing `firmware validate` command continues validating manifest declarations only. No input file is changed, no subprocess/network operation occurs, and the inspector creates no work directory or report file. Redirect stdout explicitly to a private local file if retention is wanted; shell redirection, including any overwrite, is the caller's responsibility. Never redirect into an input tree.

Structural acceptance does **not** establish product identity, vendor authenticity, compatibility or permission to extract/execute. Every receipt has `may_proceed`, `extraction_authorized` and `execution_authorized` set to `false`. There is no CLI switch to override these fields. A receipt is an observation at inspection time, not a reusable capability: any future stage must independently revalidate original bytes and obtain its own reviewed authorization.

## M1-02/V2.57 limits

These are concrete Lab intake policy limits, **not universal firmware limits or claims about vendor chunk sizes**. They are fixed in code and included in receipts; archive metadata cannot override them.

| Resource | Limit |
| --- | --- |
| Original ZIP bytes | 1 GiB |
| Total streamed/uncompressed member bytes | 2 GiB |
| Explicit ZIP/directory entries, including directories | 4,096 |
| General file/member | 256 MiB |
| Rootfs chunk | 4 MiB |
| Individual recognized metadata/signature file | 64 KiB |
| Member uncompressed/compressed ratio | 100:1 |
| ZIP central directory | 4 MiB |
| Relative path | 512 UTF-8 bytes, 12 components |
| Inspection budget | 60 seconds, checked cooperatively between bounded reads and entries |

An operating-system read that blocks cannot be interrupted by the cooperative deadline; use local, quiescent regular files. UNC/device namespace and drive-relative inputs are refused; arbitrary network-backed mounts cannot be reliably identified by the portable inspector. No arbitrary device path is opened as a firmware stream.

The ZIP end record is bounded before `zipfile` constructs its member index. Multipart, ZIP64, data-descriptor, prefixed/self-extracting archives and unsupported compression methods are refused. Extra fields are limited to Info-ZIP Extended Timestamp (`0x5455`) and New Unix UID/GID (`0x7875`) with strict field boundaries, payload grammar and duplicate rejection; timestamp and ID values are untrusted metadata and are never applied to files or used as provenance. Local and central timestamp layouts may differ, while shared modification times and duplicated UID/GID identities must agree. Only stored and deflate members are supported. Claimed sizes/ratios/counts are checked before member streaming; actual bytes, local headers, checksums, end-record count agreement and identity stability are checked during/after reading. Local-record spans include extra fields and must cover every byte before the central directory without gaps or overlap. The original ZIP digest is rechecked after member inspection. ZIP encryption is unsupported. Vendor `.enc` files are opaque byte streams, not decrypted content; their names do not mean the ZIP encryption flag is allowed.

Indexed local header/name/payload spans must cover the complete region before the central directory exactly once. Gaps, padding, overlapping aliases and unindexed local records are refused. ZIP comments remain bounded metadata covered by the original archive digest; they are not printed or treated as member files.

All members/entries are inspected, including optional non-rootfs files; there is no unbounded ignored payload area. Known archive extensions and common archive magic (including tar headers) are refused without recursion. Opaque encrypted content cannot be inspected for hidden inner formats; no claim is made about decrypted contents. Non-ASCII or nonportable member paths, absolute/drive/UNC paths, backslashes, traversal, Windows reserved names, trailing dots/spaces, duplicates, case collisions and file/directory conflicts are refused. Symlinks, reparse points, hardlinks and special files are refused. File type and identity are checked at enumeration, open and completion; directory identities are checked again before acceptance.

The inspector assumes a trusted local filesystem owner is not maliciously racing the operation. Its no-follow, file-ID, size/mtime and ancestor checks detect ordinary replacement/modification, but do not turn a mutable filesystem into a security sandbox. A later extraction stage must bind receipts to private immutable input snapshots and enforce its own stronger ownership/confinement policy. No read-only inspector can prevent the owner rewriting bytes and restoring timestamps after an observation.

## Supported package subset and strict metadata

The package root contains `ota_config.in`, with exactly one `current_version=257` and `recovery_version=18`, plus `main_os/ota_v257/manifest.sha256` and exactly 77 rootfs chunks at indices `0000..0076`. ZIPs may place this root directly at archive root or under one wrapper directory. Directory selection uses the package root; the selected tree is never searched upward or outside its boundary. A bare `ota_v257` chunk folder can be inspected for safety but is refused without its package config, rather than inferring versions from a folder name.

The main manifest row syntax is:

```text
SHA256(ota/<safe-basename>)= <64-lowercase-hex>
```

The rootfs-specific name grammar remains:

```text
rootfs.squashfs.<four-digit-index>.<64-lowercase-hex>.enc
```

Sanitized V2.57 inventory evidence identifies these eight ancillary encrypted basename shapes: `xImage.0000` through `xImage.0004`, each followed by a lowercase 64-hex filename field and `.enc`; `ota_update.in.enc`; `ota_sha256_rootfs.squashfs.<64-lowercase-hex>.enc`; and `ota_sha256_xImage.<64-lowercase-hex>.enc`. The ninth record names `manifest.sha256`, which is the controlling manifest itself. The inspector recognizes only these exact ancillary shapes, checks their direct-child paths, exact membership, role counts, unique `xImage` indices, and streamed member digests. Arbitrary `.enc` or `.sha256` names are not accepted.

The controlling manifest's `SHA256(ota/manifest.sha256)` row is self-referential. No reviewed vendor rule defines a normalization, exclusion, or other digest meaning for that row. A normal full-file SHA-256 comparison cannot verify a manifest containing its own expected digest, so the inspector validates the other records and then refuses this ancillary set with `manifest_self_reference_unverifiable`. Rootfs-only inputs retain their existing behavior. Full ancillary admission remains blocked until a reviewed checksum rule is available; the inspector does not skip the row or invent a special self-hash convention.

Rootfs names, indices and manifest membership must agree. Each encrypted chunk is SHA-256 checked against its manifest record. The filename's embedded hash is recorded separately as `filename_hash`: its meaning is not established as a ciphertext checksum by the reviewed upstream inventory source. It is not silently treated as the manifest hash or an independent trust anchor. Ancillary filename classes are recognized only for bounded inventory; their contents remain opaque, and their inclusion does not establish vendor authenticity, payload semantics, decryption safety, or execution authority.

The pinned upstream inventory script validates only rootfs records and does not establish ancillary checksum semantics. Root `md5_file_info.txt`, optional `manifest.sha256.sig`, and opaque recovery payload/manifest files under `recovery/ota_v18/` can be inventoried but are not independently authenticated or semantically validated. Receipts explicitly identify recovery validation and MD5/signature verification limits. Nonempty rootfs chunk sizes are individually measured/capped; no evidence establishes a vendor equal-length relation, so `chunk_length_consistency` stays unverified rather than imposing an invented padding rule.

This is a conservative reviewed subset, **not a claim that an actual vendor ZIP was accepted**. Unrecognized config keys, malformed lines, duplicate fields, ambiguous roots, unknown versions/recovery pairs, malformed manifest records, duplicate entries, missing/extra chunks and digest mismatches are refused. Blank config lines and CRLF/LF line endings are permitted; metadata must be UTF-8 without BOM/NUL. Unknown metadata is never executed or printed. Missing product identity is reported unverified, not invented as another config field. Unknown future firmware requires a new reviewed reference/policy rather than fallback to V2.57. The sanitized V2.57 self-reference evidence does not authorize a second ZIP inspection; new inspection requires separate owner authorization.

## Reference and source boundary

The independently pinned [data-only reference](../src/snowsky_disc_lab/data/v257-intake-reference.json) is loaded through package resources. Its raw SHA-256 is `5051401086f147476f2cf841b713fcccb518c777ad5be86c2c2b7c3b086ae1c5`; the loader checks that digest before use. A path-specific `.gitattributes` rule preserves these JSON bytes across checkouts. It contains no firmware, download URL, password, key or executable code.

Reference provenance is `eudj1n/snowsky-disc-qemu` at `85ab00deb08ac112066377fd8083cc8727ed859a`, specifically `firmware/v2.57.json` (Git blob `6ff5fb7c2371fac8b5f4cddc12dc0e6d47b9d3ca`, SHA-256 `e0bb2613eff334e3550f41a992b4b10c0bff151ddcb0c64d128eef77ec6606a9`) and parser evidence `firmware/tools/firmware_inventory.py` (blob `c59e4b27709b1c08a638ca95c6d34ec701c58245`, SHA-256 `da3d4f9582f9699b030ed86c4ccc607213f591e59cd0b14a28adaf9c0e327e0a`). Reviewed text identities were independently rechecked against [M1-01's evidence record](m1-01-runtime-preparation.json). Only selected facts and format evidence are represented in first-party data; the upstream tooling is neither copied nor imported.

The upstream profile declares product `SNOWSKY_DISC`, main/recovery 257/18, 77 rootfs chunks, reconstructed SquashFS size 80,596,992 and SHA-256 `111e4dd7ee3d7ff91ba7e61181690be7ffd22bd1bbd13ad513f5f015ffb302ae`, plus six stock-binary fingerprints. These remain upstream claims. Intake does not decrypt/reconstruct the image or observe those binaries. The package does not expose a verified product field through the reviewed intake metadata; `observed_product` is always null.

`upstreams.lock.yaml`, its source projections and existing cache identities are unchanged. No extra upstream fetch happens at runtime. The intake implementation uses the Python standard library and the already-present Pydantic/Typer stack; no new dependencies, build recipes or runtime registrations are introduced. This resolves the **intake** metadata dependency only; future extraction/runtime tooling acquisition remains separately reviewed.

## Receipt meanings and privacy

[The receipt schema](../schemas/lab-firmware-intake-v1.schema.json) is generated from `IntakeReceipt`; it is separate from the unchanged `lab-firmware/v1` manifest. Receipt fields are snake_case. Unknown schema fields are rejected by its Pydantic model. Consumers must select the exact `api_version`; future breaking receipt changes require another major version.

| Field/check | Meaning |
| --- | --- |
| `status: accepted` | All implemented bounded-inventory, supported-layout, version/chunk and declared main-manifest checks passed. No authority for later work. |
| `status: refused` | Fixed-code `conditions` include `rejected`; partial observations must not be read as acceptance. |
| `verified` condition | The named implemented check completed on these observed bytes. Scope is named, not whole-firmware verification. |
| `unverified` condition | Required evidence is absent or the property was not measured, including product/plaintext/stock binaries/authenticity. |
| `unsupported` condition | This implementation has no such check or operation, including signature trust-chain validation and execution. |
| `archive_sha256` | SHA-256 of original ZIP bytes after safety preflight and stable-file checks; null for directories/incomplete reads. |
| `package_sha256` | Lab SHA-256 of compact ASCII JSON `[[relative_path,size,sha256],...]`, sorted by relative path across all files; not a vendor package checksum. ZIP wrapper names affect it. Directories have no original ZIP identity. |
| `metadata_hashes` | Role-labelled config/main manifest/optional signature SHA-256 values; never their contents. |
| `chunks` | Main rootfs index, byte size, actual digest, expected manifest digest and opaque filename hash; no payloads. |
| `inspection_complete` | Input inventory finished; structural acceptance still requires `status: accepted`. |
| `rootfs_reference_*` | Upstream reference only, not a measured plaintext rootfs identity. |
| `may_proceed` / authorization fields | Always false; future stage/compatibility approval is not implemented. |

Receipt parsing also checks cross-field semantics. An `accepted` intake must include the complete V2.57 structure and ordered 77 chunk records, consistent manifest digests and counters, the exact bundled reference identity, fixed inspection limits, and the required condition states. A `refused` receipt may contain partial observations but must include a rejection and cannot claim verified structure. Revalidating an existing model instance catches mutation of its nested lists. Workspace staging and finalization compare the complete receipt from the candidate with a fresh inspection of the snapshot; matching only the package digest is insufficient. Workspace receipt JSON rejects duplicate object keys. These checks bind reported observations to the local bytes; they do not authenticate the vendor or grant authority.

## M1-03 — private workspace preparation

The separate `disc-lab firmware workspace` group creates a bounded, ignored local snapshot after a fresh M1-02 inspection. It keeps inspection separate from extraction:

```sh
uv run disc-lab firmware workspace stage /local/private/candidate.zip --format json
uv run disc-lab firmware workspace finalize <workspace-id> --format json
uv run disc-lab firmware workspace prepare /local/private/package --format json
uv run disc-lab firmware workspace verify <workspace-id> --format json
uv run disc-lab firmware workspace list --format json
```

`stage` creates an exclusive random session under the default `.lab/firmware-workspaces` store, copies the original ZIP bytes or the selected OTA directory into a private `inputs/` snapshot, rechecks the original after copying, and independently inspects the snapshot. `finalize` rechecks the snapshot and atomically publishes it under `workspaces/sha256-<package-digest>/<session-id>`. `prepare` performs both steps. Each session has its own `inputs/`, `intermediate/`, `extraction/`, and `diagnostics/` directories. Sessions for matching package identities do not share mutable state.

Snapshots preserve source bytes; the selected candidate is opened read-only and never modified. ZIP snapshots remain ZIP files; directory snapshots are bounded copies whose sorted path/size/content-hash inventory must match the intake package identity. A mismatch, interruption observed by the process, incomplete publication, or unsafe workspace state is refused and retained under `quarantine/`. Atomic publication uses same-volume no-replace rename semantics on Windows and Linux; unsupported Linux kernels/filesystems fail closed. A process killed without cleanup can leave a `staging` or `publishing` session; `list` reports it and an explicit `quarantine` operation retains it for review. There is no automatic deletion or stale-PID decision.

The versioned [`lab-firmware-workspace/v1` receipt schema](../schemas/lab-firmware-workspace-v1.schema.json) stores the nested pathless intake receipt, package digest, session/firmware IDs, snapshot count/bytes, condition statuses, and fixed authority fields. Reports do not contain local paths or arbitrary metadata. They do contain firmware/package/chunk hashes and should remain private. `operation_status: accepted` and `state: finalized` mean only that this local snapshot matched the structural intake identity. `may_proceed`, `extraction_authorized`, and `execution_authorized` remain `false`; compatibility and vendor authenticity remain `unverified`. The synthetic test fixtures do not grant permission to process real firmware.

### M1-03/V2.57 workspace and synthetic-output limits

These local workspace policy limits are distinct from and do not widen the M1-02 intake limits above. They are not universal firmware limits.

| Resource | Limit |
| --- | --- |
| Snapshot input | 2 GiB, also bounded by the stricter M1-02 archive/member/total limits |
| Single workspace file | 256 MiB for directory members and future work artifacts; the retained original ZIP is capped at 1 GiB by M1-02 |
| Session storage, including inputs and future work areas | 4 GiB |
| Entire workspace store | 8 GiB |
| Retained sessions across staging, finalized and quarantine | 32 |
| Entries in the entire store | 65,536 |
| Internal workspace receipt/owner metadata file | 256 KiB |
| Workspace-relative path | 768 UTF-8 bytes, 16 components |
| Copy/store inventory budget | 300 seconds, checked cooperatively |
| Synthetic harness output | Exactly 2 fixed files; 8 KiB per file and 16 KiB total |
| Synthetic operation receipt reservation | 16 KiB per receipt during quota preflight and atomic updates |

The snapshot remains bounded to the M1-02/V2.57 inspection policy; the larger session/store quotas reserve bounded space for future reviewed intermediate products. The manager remeasures the entire session and store before writing, while producing outputs, before publication, and during later verification. Receipts record measured byte and entry usage before and after the operation; metadata replacement also reserves space for a bounded temporary receipt.

`extract_synthetic` recognizes only the first-party synthetic package identity `21ae742cbc9cf0e191b818e9558109360f9aa4a3fdea1a16bb4ebe5f0c05644b`, generated by the repository's deterministic 77-chunk fixture. This package digest is the M1-03 harness allowlist; a caller-provided label is not accepted as proof. The harness writes only two fixed, digest-derived synthetic files to `extraction/synthetic-v1/outputs/`, hashes them back from disk, compares the complete output set with its expected manifest, and uses no-replace directory publication. The versioned [`lab-firmware-synthetic-extraction/v1` receipt schema](../schemas/lab-firmware-synthetic-extraction-v1.schema.json) records the workspace/input/operation identities, expected and observed output hashes, byte/entry usage and publication state. It contains no local path or firmware payload.

The synthetic operation is a filesystem lifecycle fixture, not a decryptor, archive extractor, rootfs result or compatibility test. It does not set extraction or execution authorization. `may_proceed`, `extraction_authorized`, and `execution_authorized` stay false; vendor authenticity and compatibility stay unverified. A structurally accepted real package has a different content identity and is refused by this operation. Synthetic success grants no authority to extract or execute actual firmware.

Write failures and observed interruption retain the partial output and a pathless receipt in an `incomplete-<operation-id>` directory. Repeated operations refuse existing published or incomplete output; no partial result is resumed. A hard process kill can leave a `staging-<operation-id>` directory, an atomic-receipt temporary file, or a receipt whose state remains incomplete; the directory name and receipt are never promoted automatically. The existing cleanup command remains limited to an explicitly selected empty input-staging skeleton and cannot delete extraction output. Same-user filesystem races and administrator access remain outside the threat model, and the harness itself launches no subprocess or isolation boundary.

The published M1-02 `IntakeReceipt.policy` identifier is `m1-02-v257`. It is a public field in `lab-firmware-intake/v1`, and its value identifies the reviewed V2.57 policy. Renaming it in place would silently change a published contract; preserve it for v1 and use an explicitly versioned migration if a future policy-neutral identifier is required.

Linux directories are created with owner-only permissions and snapshot files are made read-only. On Windows the store uses the selected parent directory's inherited ACL; select a location private to the current account. The implementation does not rewrite or independently audit Windows ACLs. The supported local threat model assumes a trusted, quiescent filesystem owner; same-user replacement races and administrator access are outside the protection boundary. No mounts, USB, subprocesses, network requests, elevated privilege, Docker or QEMU are used.

`quarantine` retains the selected session and its bytes. `cleanup` can remove only an explicitly selected empty staging skeleton; it refuses any session retaining input bytes, every finalized session, and quarantine. Completed sessions and quarantines have no automatic retention expiry. Their local ignored store consumes the documented quota until a separately reviewed retention policy exists.

Receipts contain no local paths, original filenames outside the constrained chunk identity, arbitrary metadata values, raw exceptions, archive comments, signature bytes or payload content. They may contain firmware/package fingerprints; keep them local by default and review before sharing. No automatic export, report persistence, cleanup or upload exists. Rejected inputs stay untouched. File atime may change through normal OS reads; source contents are not written.

## Remaining gates and next milestone

Vendor authenticity remains **unverified**, including when manifest checks pass or a signature file is present. Trust-anchor provenance, exact signed bytes/scope, rotation/revocation and policy are unresolved. There is no trusted full ZIP checksum, no reviewed actual-vendor-package acceptance and no plaintext/binary/product verification. M1-01's image/toolchain/shim/build, relevant licensing/redistribution, dedicated-VM and Windows runtime gates remain open.

M1-03 supplies the synthetic-only private snapshot, ownership, quota, verification, quarantine, limited cleanup and fixed output-lifecycle harness. The milestone remains open: no proprietary extractor, decrypted image, rootfs mount or firmware output has been implemented. The next narrow step is a separately reviewed local extraction proposal that pins the decryptor/SquashFS toolchain and exact input/output checks, then closes lawful firmware provenance, vendor authenticity, licensing and isolation decisions before any real decryption/extraction. Recheck ciphertext identity at that stage, then verify the reconstructed image and stock binaries against references. Stock V2.57 QEMU execution remains gated on M1-01's built and tested runner/shim/patch identities and the firmware/licensing/isolation gates. No QEMU, mounting, player patch or device operation is implied by the synthetic harness.

## Verification recorded for this foundation

On Windows/Python 3.14, the final firmware-free suite passed **195 tests, with 3 platform skips** (the existing FIFO case, intake FIFO case and case-sensitive sibling-name case). The tests cover ZIP/directory acceptance, malformed metadata, missing/extra chunks, checksum/CRC failures, path/link/special-file refusal, size/count/ratio caps, header/end-record mismatch, unindexed ZIP gaps/local records, mutating input and no network/subprocess/input writes. The same-size timestamp-restored ZIP mutation regression caught and verified the unbuffered-read fix; hidden ZIP records/gaps were reproduced before the contiguous-span fix. Ruff lint/format, `ty check`, JSON-schema/model equality, reference-byte/provenance checks and whitespace checks passed.

Actual CLI process checks accepted generated directory/ZIP samples with 77 chunks and false authority fields, and refused a missing synthetic path with exit 2/valid JSON. A built first-party wheel loaded the pinned reference through package resources and exercised the refusal CLI. All three existing upstream projections passed offline source verification; source locks/manager, manifest models/schemas, dependencies and existing CI definitions were preserved. Hosted Linux/Windows PR checks provide separate exact-head evidence; these local results do not claim Linux runtime, firmware or hardware acceptance.

During the original foundation verification, no actual firmware was acquired or inspected, no proprietary payload was extracted/decrypted/modified/executed, and no upstream setup, QEMU, Docker runtime, USB, flashing or external UI was invoked. The later read-only candidate inspection recorded below did not extract or execute firmware. No package was published; Lab licensing and build reproducibility remain unresolved release gates.

## M1-02/M1-03 intake and M1-04 admission follow-up (2026-10-24)

The owner-supplied V2.57 candidate was present and its filename, byte length and SHA-256 were recorded in a private local observation file. The existing `disc-lab firmware inspect --format json` workflow ran against it without modifying the candidate. It exited 2 with `status: refused`, `inspection_complete: false`, and the fixed code `zip_extra_fields_unsupported`. The inspector did not establish package versions, manifest membership or ciphertext chunk hashes. The full receipt and identity remain private. The unsupported ZIP metadata was not parsed or trusted, and the accepted ZIP subset was not widened.

The intake boundary now validates accepted receipts against their measured structure, fixed M1-02 limits and pinned data-only V2.57 reference. Snapshot stage/finalize/verify require equality with the complete fresh intake receipt, including condition states, counters, limits and metadata/chunk identities. Workspace JSON also rejects duplicate keys. The workspace execution condition retains its v1 creation-state code as a historical diagnostic; the current workspace lifecycle state is validated separately. This closes a receipt consistency gap; it does not change the trust meaning of a structurally accepted package.

### M1-04 admission checklist

| Gate | Status | Supporting observation / remaining work |
| --- | --- | --- |
| Owner V2.57 ZIP present and privately identified | PASS | Candidate present; identity retained locally and omitted from shared output. |
| Read-only bounded inspection executed | PASS | Existing inspector ran and left the candidate unchanged. |
| Structural package acceptance | FAIL | Inspector refused admission under the reviewed subset with `zip_extra_fields_unsupported`; this does not establish that the package is malformed. No parser relaxation was made. |
| Declared ciphertext/chunk hashes | NOT RUN | Inspection stopped before package structure and manifest checks. |
| Vendor provenance/authenticity | BLOCKED | No reviewed vendor trust anchor, signed-byte scope or authenticated checksum policy. |
| Extraction permission and reproducible extractor | BLOCKED | The five upstream extractor/profile/inventory source and data files are identified at a pinned commit but remain outside the managed source projection and need license review. OpenSSL and `squashfs-tools` package versions and `.deb` hashes are null; exact binaries are unmeasured. The Lab root license is unset and firmware-tool licensing is not cleared. See [M1 extraction toolchain readiness](M1-EXTRACTION-TOOLCHAIN-READINESS.md); bounded output/process controls and separate authorization also remain open. |
| Rootfs and stock binary identities | NOT RUN | No decryption, extraction or binary measurement occurred. |
| Firmware-free QEMU build and patch identities | PASS | Existing hosted Linux build/repeat evidence recorded in [M1-07](M1-07-WINDOWS-WSL2-VALIDATION.md) measured QEMU and shim identities and an identical clean repeat. |
| Trusted isolated stock runtime | BLOCKED | The firmware-free build evidence does not establish a dedicated isolated runtime or stock boot; selected artifacts still need local rehash/review before any separately authorized stock run. |
| Windows/WSL2 isolation | NOT RUN | No Windows/WSL2 extraction or stock runtime was attempted. |
| Stock boot, input, PCM and lifecycle acceptance | NOT RUN | No stock firmware session was executed; synthetic evidence does not satisfy this gate. |

M1-02 remains open because the candidate was refused by the reviewed subset and authenticity is unresolved. M1-03 remains open because no real firmware workspace was prepared and no extraction output exists. M1-04 remains **NOT RUN / UNVERIFIED**. The candidate result does not establish that the package is malformed; it establishes only that this inspector does not support its ZIP extra fields.
