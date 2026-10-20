# Firmware extraction toolchain and execution readiness

**Status:** source review and gate definition only. No firmware was acquired, decrypted, extracted, mounted, or executed. No upstream code, OpenSSL, SquashFS tool, Docker image, or QEMU runtime was run or built. M1-01, M1-02, and M1-03 remain open.

This review uses the locked integration source `eudj1n/snowsky-disc-qemu` commit [`85ab00deb08ac112066377fd8083cc8727ed859a`](https://github.com/eudj1n/snowsky-disc-qemu/tree/85ab00deb08ac112066377fd8083cc8727ed859a). The existing source lock includes selected controller, emulator, library, test, viewer, documentation, and license paths; it does not project the upstream `firmware/` tree. The files below remain separate source evidence in [`m1-01-runtime-preparation.json`](m1-01-runtime-preparation.json), not executable managed-cache inputs. Existing source projections and identities are unchanged.

## Pinned upstream extraction source

Each row identifies upstream bytes at the same immutable commit. SHA-256 and Git blob IDs are source identities only; they do not establish license clearance, firmware authenticity, or permission to execute the code.

| Upstream file | Git blob | SHA-256 | Role |
| --- | --- | --- | --- |
| [`firmware/tools/firmware_extract.py`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/firmware/tools/firmware_extract.py) | `79ff054a740ed44c57e08a2608348a12e876012c` | `b88e7ae65a038fd8691a18de8b6f980655ae2a90c46ecf3b79cf89cc6c27a5bd` | Concatenated rootfs verification and `unsquashfs` invocation |
| [`firmware/tools/firmware_inventory.py`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/firmware/tools/firmware_inventory.py) | `c59e4b27709b1c08a638ca95c6d34ec701c58245` | `da3d4f9582f9699b030ed86c4ccc607213f591e59cd0b14a28adaf9c0e327e0a` | Version, chunk-manifest and optional archive checks; streaming decrypt/hash helper |
| [`firmware/profile.py`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/firmware/profile.py) | `273cce7859d645efc4eb8ab6bb5343ac464ec04c` | `06e30dfb68006948d72a67ecf3d1d058feedf2293695c2adf98d0667e4e05262` | Version selection, profile validation, six binary fingerprints, key-patch metadata |
| [`firmware/v2.57.json`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/firmware/v2.57.json) | `6ff5fb7c2371fac8b5f4cddc12dc0e6d47b9d3ca` | `e0bb2613eff334e3550f41a992b4b10c0bff151ddcb0c64d128eef77ec6606a9` | Data-only V2.57 profile claims |
| [`firmware/active-version`](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/firmware/active-version) | `7521537d96663385b29fcf2863ca2d8b2a4d601c` | `614c56cf1dbf19349b8e7fd1fc7efdd918e1aa382b8faf6a55b83e220157bdfb` | Five bytes `2.57\n`; read by `profile.py` at import time |

The four preexisting source identities were checked against the ignored, previously reviewed public-text cache. `active-version` was retrieved at the pinned commit through GitHub's contents API; its decoded five bytes were independently checked against both the Git blob and SHA-256. No firmware or complete upstream tree was fetched. The extractor's import closure is these files plus Python's standard library; importing `profile.py` also requires the adjacent `active-version` and profile JSON files.

## What the upstream tools actually do

`firmware_extract.py` expects an already unpacked OTA directory. It reads the selected profile (defaulting through `active-version`), scans `rootfs.squashfs.*.enc`, rejects a nonmatching chunk name, direct symlink, non-file, duplicate index, or index set other than `0..76`, and refuses an already existing destination. It does **not** parse the package's `ota_config.in`, verify main/recovery versions, verify `manifest.sha256`, compare the original ZIP, or verify a manifest signature.

For each chunk, the extractor calls `firmware_inventory.plaintext_digest`, which starts an OpenSSL subprocess using AES-256-CBC, PBKDF2, 10,000 iterations, and the upstream literal passphrase `fo123`. It streams the concatenated plaintext to a temporary file beside the requested destination, computes SHA-256 and size, and checks SquashFS little-endian magic `hsqs`. Extraction stops unless that result equals the profile's rootfs digest and size. It then invokes `unsquashfs -no-progress -no-xattrs -d DEST /proc/self/fd/N`, passing the temporary file descriptor. This path requires Linux `/proc` and file-descriptor passing; the script is not a native Windows extraction path.

The separate inventory command can check `ota_config.in` main/recovery version values, contiguous chunk names, `manifest.sha256` membership and encrypted-chunk hashes. With an archive, it can compare selected ZIP chunks and `ota_config.in` with the unpacked directory. It reports `manifest_signature_verified: false`; these checks establish byte consistency only. The extractor does not call this inventory path, so an integration must independently revalidate the snapshot and the checks required by Lab policy before invoking any decryptor.

If OpenSSL fails, the helper raises an error. A plaintext digest mismatch prevents `unsquashfs`. A failed `unsquashfs` subprocess raises, but the upstream script does not quarantine or remove a partially created destination; its next attempt refuses that destination as already existing. It has no process timeout, memory limit, disk quota, output-tree inventory, or containment check for symlinked parent directories. Its direct chunk symlink check does not provide the workspace manager's ownership, no-follow, mount-boundary, or race checks.

`profile.py` is a separate static verification step, not part of extraction. It checks product, main OS version, recovery OS version and six binary hashes. For `usr/bin/mq_player`, it recognizes stock or key-patched bytes only by normalizing the patch site to the stock bytes and rechecking the stock whole-file hash plus ELF32 little-endian MIPS executable-segment mapping. The profile records the patch at file offset `0xe7300`, virtual address `0x4e7300`, bytes `41004292` → `01000224`; its patched output SHA-256 is null. The upstream profile permits patching, but this task neither performs nor authorizes it.

## V2.57 reference identities and meanings

The data-only profile claims product `SNOWSKY_DISC`, main version `257`, recovery version `18`, exactly 77 rootfs chunks, reconstructed image size `80,596,992` bytes, and SHA-256 `111e4dd7ee3d7ff91ba7e61181690be7ffd22bd1bbd13ad513f5f015ffb302ae`. It also lists the original stock hashes for `usr/bin/mq_player`, `usr/bin/mq_ui`, `bin/busybox`, `lib/ld-2.29.so`, `lib/libc-2.29.so`, and `usr/lib/libtinyalsa.so.1.1.1`. These are upstream profile claims, not measurements of locally supplied firmware.

Keep these checks distinct:

| Evidence | Meaning | Present upstream behavior |
| --- | --- | --- |
| Encrypted chunk SHA-256 | Detects chunk byte mismatch against `manifest.sha256` | Separate inventory command only; extractor skips it |
| Product/main/recovery metadata | Selects the expected product and profile | Separate inventory/profile validation; extractor does not enforce package metadata |
| Vendor signature trust chain | Establishes vendor authenticity for explicitly signed bytes | Unsupported; inventory marks signature verification false and no trust anchor is pinned |
| Reconstructed rootfs size/SHA-256 | Matches concatenated decrypted bytes to the profile claim | Enforced by extractor before filesystem extraction; still an upstream claim until measured against lawful local input |
| SquashFS tree | Materializes files from the verified image | `unsquashfs` writes a directory; no tree manifest or output quota is produced by upstream code |
| Six original stock binary hashes | Identifies known extracted stock files | Separate `profile.validate` operation; extractor does not invoke it |
| Emulator-specific player change | Distinguishes original stock bytes from a derived patched binary | Profile describes one key-patch operation; patched-output hash is unmeasured |

No intake receipt alone authorizes decryption, extraction, patching, or execution. A matching checksum or profile hash is not vendor authentication, a license grant, compatibility evidence, or owner authorization.

## Toolchain and immutable runtime identities

The extraction code uses Python standard library, OpenSSL CLI, and `unsquashfs` from `squashfs-tools`. The M1-01 recipe requests Debian packages `openssl` and `squashfs-tools`, but their resolved versions and `.deb` SHA-256 values remain null in the runtime record. No OpenSSL or SquashFS binary hash/version has been measured, and no build output hash may be inferred from the source record.

The adjacent stock-QEMU preparation remains separately pinned to the upstream integration commit above, Debian base image `debian:12@sha256:6ebd97fa83deb272194a2cf015b3d26a4d538e9ad3a7a79d544c8af5b0a01443` (`linux/amd64` child `sha256:2f65600e1252c5649d2213e1d1ea4d74253d26514dc6530102a875e429245929`), and Debian snapshot `20260910T000000Z`. The intended Debian QEMU package version is `1:7.2+dfsg-7+deb12u18`. Its source descriptor SHA-256 is recorded as `6b6bd27b947ec89e40a1d6b26d9c9f3c698ca691da13163e0483f6061bbb20b3`, and the QEMU source archive and Debian delta hashes are recorded, but the descriptor signature and archive bytes have not been verified by the Lab. Package versions and archive checksums, compiler version, cross sysroot digest, final runtime image digest, QEMU executable hash, and shim hashes remain unmeasured/null. The upstream QEMU device patch has a pinned source hash in the M1-01 record; that does not identify a built QEMU binary.

The current source projection deliberately excludes the firmware tools. A future source-only dependency, if approved, must be an independently reviewed, minimal projection for the extractor, inventory helper, profile, `active-version`, and V2.57 data at the exact commit above. It must include license evidence and be separate from the existing `snowsky-disc-qemu` projection. This task does not add a source-lock identity or alter cached paths.

## Required isolation and output boundary

The current `FirmwareWorkspaceManager` provides owned local snapshots, receipt revalidation, quotas, and no-replace publication for its existing operations. The synthetic harness accepts only one first-party fixture digest. Neither provides a process sandbox or authority to run upstream code. Its current workspace per-file cap and synthetic output policy are not proven suitable for a reconstructed rootfs tree.

Before a future real extraction operation, the reviewed boundary must:

1. Independently verify workspace ownership and rehash the finalized snapshot immediately before use. Treat intake/workspace receipts as evidence, not authorization. Keep the source snapshot immutable and mount it read-only.
2. Run one nonprivileged extraction session in a dedicated disposable Linux VM with no network, host secrets, physical devices, Docker socket, shared home directory, or writable source mount. A Python process or Docker container alone is not the sandbox. Any container layer must remain inside this VM and drop unnecessary capabilities.
3. Put outputs on a separate quota-capped writable filesystem. Enforce memory, CPU, wall-clock and disk limits outside the upstream process; the current workspace manager cannot limit subprocess resources or contain `unsquashfs` writes.
4. Check input archive identity and metadata under M1-02 policy, independently verify encrypted chunks, decrypt to a private temporary image, require the exact V2.57 image size/hash, then extract into a fresh run-owned directory. Validate product/version metadata and the six stock binary fingerprints before accepting a tree. Keep any key-patched player as a separately identified derivative with a measured output hash.
5. Publish only a complete verified output directory with no-replace semantics. On timeout, signal, decryption failure, digest mismatch, or partial filesystem extraction, retain the run-owned output and receipt in quarantine; never retry into or clean an ambiguous destination automatically.

VM image identity, no-network enforcement, secret/device/socket absence, resource limits, writable-mount confinement, interrupt teardown, quarantine, and WSL2 behavior require actual Linux and Windows/WSL2 acceptance. They cannot be claimed from the Python workspace manager or synthetic tests alone.

## Gate matrix

| Gate | Evidence now | Status and closure needed |
| --- | --- | --- |
| Required input and exact identities | M1-02 bounded structural inspector and M1-03 owned snapshots; no real archive hash or measurement | **Blocked.** Owner-supplied lawful input, independent snapshot revalidation, exact ZIP/package identity, metadata, and encrypted-chunk checks must be reviewed together |
| Vendor provenance/authenticity | No archive hash, vendor trust anchor, signed-byte scope, or verified signature chain | **Blocked.** Resolve the trust chain or a clearly limited owner-approved provenance policy before any real decryption; checksum matching cannot satisfy this gate |
| Toolchain source and utilities | Five exact source/data files identified above; Python standard library; OpenSSL and `unsquashfs` package requests known | **Blocked.** Resolve the minimal source-only projection and its license evidence; pin exact OpenSSL/SquashFS and full Debian package BOM with authenticated metadata and archive hashes |
| QEMU build artifacts | Base image, platform child, snapshot date, QEMU package/source descriptor, source archives and patch source identity recorded | **Blocked.** Verify signed Debian metadata and source archives, resolve compiler/sysroot, build in the approved VM, measure image/QEMU/shim hashes, and compare repeated builds |
| Licensing and rights | Existing license inventory is explicitly initial; firmware tools/firmware are outside its cleared projection; QEMU patch/external QEMU is `NOASSERTION`; Lab root license is unset | **Blocked for affected use/distribution.** Review exact extractor/tool licenses, vendor firmware rights, Debian/toolchain notices, QEMU/patch provenance and source obligations before processing or distributing outputs |
| Isolation | Workspace ownership and storage checks exist; no extraction VM has been built or accepted | **Blocked.** Verify the dedicated VM, nonprivileged/no-network boundary, quotas, mount confinement, failure retention and Windows/WSL2 path |
| Expected output and stock identity | Upstream rootfs and six stock-binary claims; no measured local outputs or patched-player digest | **Blocked.** Verify rootfs size/hash, extracted metadata, all six original binaries, and any separately patched derivative against measured outputs |
| Explicit authorization | Existing receipts retain false authority fields; this task processes no proprietary firmware | **Blocked.** Require separate explicit approval after the source, rights, provenance and isolation gates close; structural acceptance alone never authorizes a later stage |

### Optional follow-up

Resolve optional `aiohttp` licensing only if the controller environment is redistributed. UI/font and screenshot-rights review applies only if those assets are bundled or published. Those items do not close the extraction or runtime gates above.

## Next executable milestone

Real extraction remains blocked by unverified vendor provenance/authenticity and unresolved tool/source licensing, so the next technical task should be the **firmware-free M1-01 QEMU runtime build**. It should verify the signed Debian snapshot/package BOM and QEMU source inputs, pin the compiler/sysroot, build the QEMU binary and shims inside the dedicated disposable VM without any firmware mounted, record measured artifact hashes, and perform a repeat-build comparison. Keep the runtime milestone open until Linux and WSL2 isolation and exact artifact evidence pass. Return to real extraction integration only after vendor provenance, rights, the minimal source projection, and extraction resource/output limits receive explicit review.

No runtime validator or extractor was added: the existing workspace interface has no safe subprocess or authenticity contract to reuse, while the tool versions, rights, and VM boundary are still unverified. Adding an always-blocked readiness command or a duplicate toolchain manifest would not make those prerequisites executable.
