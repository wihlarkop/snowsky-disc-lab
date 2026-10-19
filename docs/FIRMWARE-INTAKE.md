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

The ZIP end record is bounded before `zipfile` constructs its member index. Multipart, ZIP64, data-descriptor, prefixed/self-extracting archives, unsupported compression methods and ZIP extra fields are refused. Only stored and deflate members are supported. Claimed sizes/ratios/counts are checked before member streaming; actual bytes, local headers, checksums, end-record count agreement and identity stability are checked during/after reading. The original ZIP digest is rechecked after member inspection. ZIP encryption is unsupported. Vendor `.enc` files are opaque byte streams, not decrypted content; their names do not mean the ZIP encryption flag is allowed.

Indexed local header/name/payload spans must cover the complete region before the central directory exactly once. Gaps, padding, overlapping aliases and unindexed local records are refused. ZIP comments remain bounded metadata covered by the original archive digest; they are not printed or treated as member files.

All members/entries are inspected, including optional non-rootfs files; there is no unbounded ignored payload area. Known archive extensions and common archive magic (including tar headers) are refused without recursion. Opaque encrypted content cannot be inspected for hidden inner formats; no claim is made about decrypted contents. Non-ASCII or nonportable member paths, absolute/drive/UNC paths, backslashes, traversal, Windows reserved names, trailing dots/spaces, duplicates, case collisions and file/directory conflicts are refused. Symlinks, reparse points, hardlinks and special files are refused. File type and identity are checked at enumeration, open and completion; directory identities are checked again before acceptance.

The inspector assumes a trusted local filesystem owner is not maliciously racing the operation. Its no-follow, file-ID, size/mtime and ancestor checks detect ordinary replacement/modification, but do not turn a mutable filesystem into a security sandbox. A later extraction stage must bind receipts to private immutable input snapshots and enforce its own stronger ownership/confinement policy. No read-only inspector can prevent the owner rewriting bytes and restoring timestamps after an observation.

## Supported package subset and strict metadata

The package root contains `ota_config.in`, with exactly one `current_version=257` and `recovery_version=18`, plus `main_os/ota_v257/manifest.sha256` and exactly 77 rootfs chunks at indices `0000..0076`. ZIPs may place this root directly at archive root or under one wrapper directory. Directory selection uses the package root; the selected tree is never searched upward or outside its boundary. A bare `ota_v257` chunk folder can be inspected for safety but is refused without its package config, rather than inferring versions from a folder name.

The reviewed chunk-name grammar is:

```text
rootfs.squashfs.<four-digit-index>.<64-lowercase-hex>.enc
SHA256(ota/<chunk-basename>)= <64-lowercase-hex>
```

Rootfs names, indices and manifest membership must agree. Each encrypted chunk is SHA-256 checked against its manifest record. The filename's embedded hash is recorded separately as `filename_hash`: its meaning is not established as a ciphertext checksum by the reviewed upstream inventory source. It is not silently treated as the manifest hash or an independent trust anchor.

The accepted main manifest is limited to the pinned rootfs-record grammar above. Other main payload records (including kernel/update payloads) require further reviewed format evidence and are conservatively refused; the inspector does not invent a generic vendor manifest format. Root `md5_file_info.txt`, optional `manifest.sha256.sig`, and opaque recovery payload/manifest files under `recovery/ota_v18/` can be inventoried but are not independently authenticated or semantically validated. Receipts explicitly identify recovery validation and MD5/signature verification limits. Nonempty rootfs chunk sizes are individually measured/capped; no evidence establishes a vendor equal-length relation, so `chunk_length_consistency` stays unverified rather than imposing an invented padding rule.

This is a conservative reviewed subset, **not a claim that an actual vendor ZIP was accepted**. Unrecognized config keys, malformed lines, duplicate fields, ambiguous roots, unknown versions/recovery pairs, malformed manifest records, duplicate entries, missing/extra chunks and digest mismatches are refused. Blank config lines and CRLF/LF line endings are permitted; metadata must be UTF-8 without BOM/NUL. Unknown metadata is never executed or printed. Missing product identity is reported unverified, not invented as another config field. Unknown future firmware requires a new reviewed reference/policy rather than fallback to V2.57.

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

Receipts contain no local paths, original filenames outside the constrained chunk identity, arbitrary metadata values, raw exceptions, archive comments, signature bytes or payload content. They may contain firmware/package fingerprints; keep them local by default and review before sharing. No automatic export, report persistence, cleanup or upload exists. Rejected inputs stay untouched. File atime may change through normal OS reads; source contents are not written.

## Remaining gates and next milestone

Vendor authenticity remains **unverified**, including when manifest checks pass or a signature file is present. Trust-anchor provenance, exact signed bytes/scope, rotation/revocation and policy are unresolved. There is no trusted full ZIP checksum, no reviewed actual-vendor-package acceptance and no plaintext/binary/product verification. M1-01's image/toolchain/shim/build, relevant licensing/redistribution, dedicated-VM and Windows runtime gates remain open.

Next: a narrowly scoped **M1-03 isolated extraction preparation** design, first proving synthetic per-run ownership, immutable input binding, no-replace private staging, quotas, path/link confinement, interruption quarantine and bounded cleanup. Separately review a pinned decryptor/SquashFS toolchain and vendor provenance policy before any real decryption/extraction. Recheck ciphertext identity at that stage, then verify the reconstructed image and stock binaries against references before any further action. No QEMU, mounting, player patch or device operation is implied by this foundation.

## Verification recorded for this foundation

On Windows/Python 3.14, the final firmware-free suite passed **195 tests, with 3 platform skips** (the existing FIFO case, intake FIFO case and case-sensitive sibling-name case). The tests cover ZIP/directory acceptance, malformed metadata, missing/extra chunks, checksum/CRC failures, path/link/special-file refusal, size/count/ratio caps, header/end-record mismatch, unindexed ZIP gaps/local records, mutating input and no network/subprocess/input writes. The same-size timestamp-restored ZIP mutation regression caught and verified the unbuffered-read fix; hidden ZIP records/gaps were reproduced before the contiguous-span fix. Ruff lint/format, `ty check`, JSON-schema/model equality, reference-byte/provenance checks and whitespace checks passed.

Actual CLI process checks accepted generated directory/ZIP samples with 77 chunks and false authority fields, and refused a missing synthetic path with exit 2/valid JSON. A built first-party wheel loaded the pinned reference through package resources and exercised the refusal CLI. All three existing upstream projections passed offline source verification; source locks/manager, manifest models/schemas, dependencies and existing CI definitions were preserved. Hosted Linux/Windows PR checks provide separate exact-head evidence; these local results do not claim Linux runtime, firmware or hardware acceptance.

No actual firmware was acquired or inspected, no proprietary payload was extracted/decrypted/modified/executed, and no upstream setup, QEMU, Docker runtime, USB, flashing or external UI was invoked. No package was published; Lab licensing and build reproducibility remain unresolved release gates.
