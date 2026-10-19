# Initial source-projection license inventory

**Reviewed:** 2026-10-20.
**Scope:** the three pinned, source-only projections in [`upstreams.lock.yaml`](../upstreams.lock.yaml).

This is an initial inventory of major component families, not a complete file-level dependency audit, legal clearance, or conclusion that every source file may be redistributed in every form. The source lock remains the authority for repository identities, exact commits, selected license-text hashes, and projection boundaries. Each identified record below is tied to immutable commit evidence and raw SHA-256 values in [`license-inventory.json`](license-inventory.json). Evidence files were read from locally cached projections that passed the source manager's offline verification during preparation.

The root license for this Lab repository is still unset. This inventory does not choose one. Upstream repository-level MIT labels do not override the separately declared GPL-3.0-or-later UI license or component-specific third-party terms.

## Findings and follow-up gates

| Pinned source | Identified major families | Pending review gates |
| --- | --- | --- |
| `diskos` at `4cd4a60003944b0cf4e8e5fb9feac2d07ea87df9` | Installer/tooling MIT; on-device UI GPL-3.0-or-later; LVGL 9.2.2 MIT; FreeType offered under FTL or GPL-2.0-or-later (the UI README selects FTL); embedded font and icon glyph data OFL-1.1; vendored LZ4 BSD-2-Clause. | SQLite, jsmn, md5, TJpgDec and qrcodegen need exact per-component notices/version and attribution checks; the UI README references TJpgDec and qrcodegen license files that are absent from this selected projection. Normalize the SQLite and md5 public-domain claims before redistribution. Review FreeType's driver and module-specific license scopes. |
| `disco` at `485fe0ff685b3c386e679491cda74e275016b481` | Installer/tooling MIT; on-device UI GPL-3.0-or-later; LVGL 9.2.2 MIT; embedded fonts and icon glyph data OFL-1.1; Boomshine MIT; Boomshine DejaVu glyph data under Bitstream Vera, with DejaVu changes declared public domain. | SQLite, jsmn, md5, TJpgDec and qrcodegen need exact per-component notices/version and attribution checks; referenced TJpgDec and qrcodegen license files are absent from this selected projection. Normalize the public-domain claims. Review optional now-playing font source-to-output mapping and retained notices. |
| `snowsky-disc-qemu` at `85ab00deb08ac112066377fd8083cc8727ed859a` | Selected repository source/documentation MIT; controller package MIT. | Resolve and inventory optional Python dependencies before redistributing an environment. Review the QEMU device patch's provenance and target QEMU version/license before distributing patched QEMU; the QEMU implementation itself is external, not vendored in this projection. Review screenshot/image rights. Firmware is outside this inventory and must remain separately sourced and reviewed. |

For the UI font families, upstream README mappings and accompanying SIL Open Font License 1.1 texts cover generated C glyph data as identified here, including Source Han Sans. Retain the corresponding notices and review reserved font names and attribution requirements in the actual distribution package. FreeType's bundled license file offers mutually exclusive FTL and GPLv2-or-later choices; its UI README points to FTL. FreeType also calls out driver and module-specific licenses, which require file-scope review. The Disco! DejaVu notice uses Debian copyright format: Bitstream Vera applies to the font files, DejaVu changes are public domain, and a separate GPL-2+ stanza is limited to `debian/*` packaging files.

The machine-readable rows use SPDX expressions only where selected evidence supports a component-level identification. `NOASSERTION` rows are explicitly pending; they must not be read as permission to redistribute. Paths in those rows identify review scope, not a claim that every file in a directory shares one license.

## Verification limits

All three cache projections were verified locally against the lock before evidence hashes were computed. The JSON metadata test intentionally reads only this inventory and the source lock; it does not require cached upstream sources, firmware, or network access, so public CI remains firmware-free. The cache verification is preparation provenance for this inventory, not part of CI and not a substitute for future per-file review after a source pin or projection changes.

Do not copy full third-party license texts into this document. Preserve the original notices with any source or binary distribution and satisfy each component's applicable attribution and source-disclosure terms.
