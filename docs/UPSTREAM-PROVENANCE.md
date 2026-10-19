# Upstream Source Provenance

This record pins the public source references listed in [`upstreams.lock.yaml`](../upstreams.lock.yaml). It covers GitHub reference, commit, tree, and selected license metadata reviewed on **2026-10-19**. It is not a full source security review, a runtime assessment, or a claim that the upstream software is safe to execute.

## Selected immutable commits

| Source | Observed reference | Selected commit | Resolution |
|---|---|---|---|
| diskOS | `v1.2.1` annotated tag | `4cd4a60003944b0cf4e8e5fb9feac2d07ea87df9` | The GitHub tag object dereferenced to this commit; the tag and commit are unsigned. |
| Disco! | `v2.5.6` annotated tag | `485fe0ff685b3c386e679491cda74e275016b481` | The GitHub tag object dereferenced to this commit; the tag and commit are unsigned. |
| Snowsky Disc QEMU | `2.x` branch | `85ab00deb08ac112066377fd8083cc8727ed859a` | The branch is the repository default branch and resolved directly to this commit. |

Each lock entry records the complete lowercase commit SHA and its immutable GitHub commit URL. The tag and branch strings document what was observed during this review; source identity comes from the commit SHA.

## Included paths and excluded payloads

The diskOS and Disco! cache projections are limited to `ui/`, `docs/`, the root `README.md`, and root `LICENSE`. Their full Git trees also contain files outside that projection, including these executable or binary payloads:

| Excluded paths (present in both UI repository trees) | Size per file (bytes) |
|---|---:|
| `payload/mq_ui` (separate prebuilt UI executable; diskOS) | 4,285,004 |
| `payload/mq_ui` (separate prebuilt UI executable; Disco!) | 6,133,940 |
| `flash/disc_spl_lpddr3.bin` | 8,056 |
| `flash/dram_head.bin` | 96 |
| `flash/ginfo_w63ah6nkb.bin` | 384 |
| `flash/my_write5_dram.bin` | 4,704 |
| `flash/my_write6_dram.bin` | 9,232 |
| `vendor/linux-x86_64/disc_spl_lpddr3.bin` | 8,056 |
| `vendor/linux-x86_64/my_write5_dram.bin` | 4,704 |
| `vendor/linux-x86_64/my_write6_dram.bin` | 9,232 |
| `spl-src/uboot-xburst-lpddr3-src.tar.gz` | 15,397,757 |

`flash/` and `vendor/linux-x86_64/` helper blobs have identical Git object IDs across the two repositories. The diskOS and Disco! trees also contain compressed corresponding-source archives under `corresponding-source/`; the largest listed archive is `glibc_2.39.orig.tar.xz` at 18,520,988 bytes. Disco! additionally has `disc-shelf-1.0.4-source.tar.gz` at 6,228,448 bytes. These paths and sizes were identified from GitHub tree metadata only; they were not downloaded, opened, extracted, or executed. The `ui/` projections contain vendored source, generated font C files, and font/image assets, but the tree scan found no `.bin`, `.elf`, `.img`, or `.zip` payloads under `ui/`.

The QEMU projection contains `controller/`, `docs/`, `emulator/`, `library/`, `tests/`, `viewer/`, root `README.md`, root `LICENSE`, and `pyproject.toml`. It excludes the separate `firmware/` and `experiments/` trees. QEMU documentation describes supplying official firmware locally and running setup/extraction through emulator scripts; this provenance review did not acquire firmware or run those commands. The QEMU tree scan found no tracked `.bin`, `.elf`, `.img`, `.rootfs`, `.zip`, `.iso`, `.u-boot`, or compressed tar payloads.

All three recursive tree scans reported no Git submodule entries or symlinks. The diskOS tree has a root `.gitattributes` that sets `* -text`; it contains no Git LFS filter rule. The other two trees had no `.gitattributes` file. These observations describe only the selected commits.

## Selected license evidence

The lock records raw UTF-8 file SHA-256 values for the listed public license texts. The license scope is based on the content of those files and the UI README declarations; it does not reclassify unreviewed components or replace a full dependency-license audit.

| Source file | SPDX expression | Recorded scope | SHA-256 |
|---|---|---|---|
| diskOS `LICENSE` | `MIT` | Installer and tooling; `ui/README.md` separately declares the UI GPL-3.0-or-later. | `fd3cc13d72fc81a51cfc06d191ac26e3de8f3d33587ba142c89e71bd38596e06` |
| diskOS `ui/COPYING` | `GPL-3.0-or-later` | On-device UI, as explicitly declared in `ui/README.md`. | `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986` |
| diskOS `ui/licenses/LICENSE-LVGL-MIT.txt` | `MIT` | Vendored LVGL 9.2.2, as identified in `ui/README.md`. | `6a916130a36e83a79bb0dca6c6a7bfe60a67af7d118605e2b7b23bd5ad5c4eb0` |
| Disco! `LICENSE` | `MIT` | Installer and tooling; `ui/README.md` separately declares the UI GPL-3.0-or-later. | `fd3cc13d72fc81a51cfc06d191ac26e3de8f3d33587ba142c89e71bd38596e06` |
| Disco! `ui/COPYING` | `GPL-3.0-or-later` | On-device UI, as explicitly declared in `ui/README.md`. | `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986` |
| Disco! `ui/licenses/LICENSE-LVGL-MIT.txt` | `MIT` | Vendored LVGL 9.2.2, as identified in `ui/README.md`. | `6a916130a36e83a79bb0dca6c6a7bfe60a67af7d118605e2b7b23bd5ad5c4eb0` |
| QEMU `LICENSE` | `MIT` | Included controller, emulator, library, tests, viewer, and documentation paths. | `8cbb19ad3535601695a5c40583497c5e1bcbb8fddaf0e177be07a54cf15e8762` |
