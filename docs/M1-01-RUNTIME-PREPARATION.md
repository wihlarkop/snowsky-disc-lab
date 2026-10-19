# M1-01 — Pinned stock V2.57 runtime preparation

Reviewed 2026-10-20. **Preparation recorded; build and runtime blocked.** This task supplies an evidence inventory and decisions for later implementation, not an emulator runner, build approval or compatibility claim. Firmware intake, extraction, QEMU boot, external UIs, device operations and Developer Studio were NOT RUN and are not implemented here.

PR [#6](https://github.com/wihlarkop/snowsky-disc-lab/pull/6) merged as `f6ab222dac3afdc3d67efbc031046d5ad2737897`. Its [integrated-main CI](https://github.com/wihlarkop/snowsky-disc-lab/actions/runs/39299642208) completed successfully on that exact commit: Ubuntu/Windows × Python 3.12/3.14. This satisfies the M0 start gate for this preparation. It is firmware-free CLI evidence, not Docker/WSL2 acceptance.

Read with the [M1 roadmap](ROADMAP.md), [external UI ADR](adr/0001-external-ui-handoff.md), [source lock](../upstreams.lock.yaml), [license inventory](LICENSE-INVENTORY.md), [trust boundaries](TRUST-BOUNDARIES.md) and [compatibility policy](COMPATIBILITY.md).

## Evidence and immutable identities

The companion [JSON record](m1-01-runtime-preparation.json) contains SHA-256 and Git blob identities for 57 reviewed source files, exact firmware reference metadata and explicit nulls for unavailable output identities. It is a versioned **documentation record**, not a new public manifest schema, source-manager lock, allowlist or executable launch plan. No CLI consumes it. Null never means approved, optional or wildcard.

All three M0 source projections passed current offline `sources verify`. QEMU integration source remains `85ab00deb08ac112066377fd8083cc8727ed859a` from `eudj1n/snowsky-disc-qemu`, projection `ef1f0b45f86d4724a7359694b2c3bc4c`. The `2.x` branch label is discovery context only. Neither source pins nor include paths changed.

Six excluded public files were reviewed separately at that commit: `firmware/active-version`, `firmware/v2.57.json`, `firmware/profile.py`, `firmware/tools/firmware_extract.py`, `firmware/tools/firmware_inventory.py` and `firmware/docs/firmware-profiles.md`. Their decoded bytes are recorded with Git blob IDs and SHA-256 values in the evidence list below; `active-version` was fetched as the five-byte value `2.57\n` and independently hashed. This did not fetch firmware or add files to the managed cache. The five source-text files remain in ignored `.cache/m1-01-review/`.

The following links identify primary source evidence at the locked commit:

| Concern | Verified identity or observation |
| --- | --- |
| [Docker build recipe](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/docker/Dockerfile) | Both stages use `debian:12@sha256:6ebd97fa83deb272194a2cf015b3d26a4d538e9ad3a7a79d544c8af5b0a01443`. This identifies the base image index, **not** the resulting runtime image. |
| Base platform selection | Initial Lab candidate is `linux/amd64` for native Linux and x86-64 Windows/WSL2. Registry index bytes independently hash to the pinned digest; its amd64 child is `sha256:2f65600e1252c5649d2213e1d1ea4d74253d26514dc6530102a875e429245929`. Metadata only; no layers pulled. Upstream also describes arm64, which remains unaccepted by Lab. |
| [APT input](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/docker/debian.sources) | Debian and Debian Security snapshots at `20260910T000000Z`, bookworm/bookworm-updates/bookworm-security, main, Debian archive keyring, `Check-Valid-Until: no`. Signed-index and package-hash verification must remain enabled. Disabling expiry for an archived snapshot does not permit unsigned repositories. |
| QEMU implementation | Debian source `1:7.2+dfsg-7+deb12u18`, statically built for `mipsel-linux-user`; not a QEMU Git commit. Exact configure options, descriptor hash and archive metadata are in the JSON record. |
| [Debian source descriptor](https://snapshot.debian.org/archive/debian/20260910T000000Z/pool/main/q/qemu/qemu_7.2%2Bdfsg-7%2Bdeb12u18.dsc) | Descriptor declares original archive SHA-256 `91aca71520040edc40b8d437aa3004dae614f58e286cf653ee8996c07af2962f` (23,523,172 bytes), Debian delta `28a1c86310ee53b6bf1854cffe6f6be6ed29a08db7d05759f8ac57b8d6a6cb2f` (405,636 bytes). Descriptor signature and archive bytes have **not** been independently verified by Lab. No source archives downloaded. |
| [QEMU device patch](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/docker/qemu/snowsky-disc-devices.patch) | Exact patch bytes pinned in JSON. Adds framebuffer/input ioctl handling for static guests, socket-error translation and process-view behavior. It is separate from firmware binary patches. Applicable source/license provenance remains a build/distribution review gate. |
| [Shim build](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/shims/build_shims.sh) | `mipsel-linux-gnu-gcc`, `-shared -fPIC -mabi=32 -march=mips32r2 -nostdlib`; writes ELF flags bytes `07140070` at offset 36 for NaN2008. Inputs include `capture.h` and `asound.cards`, all hashed in JSON. |
| [Shim installation](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/scripts/10_setup_env.sh) | Preload order is `fbshim.so`, `asndshim.so`, `tinyshim.so`; `mqshim.so` is compiled when present but not in this preload list. Static programs bypass these dynamic interposers; static device support does not imply static audio capture. |

Dockerfile package requests are constrained by the dated snapshot, but compiler/binutils/sysroot versions and complete transitive package checksums have not been enumerated. The patched QEMU executable, shim outputs and final runtime image do not exist as Lab-measured artifacts. The upstream 12-character QEMU build-directory suffix is not a substitute for full SHA-256.

## Reproducible preparation strategy

Select the pinned upstream recipe and snapshot as the baseline candidate. Do not substitute a floating Debian tag, current APT mirror, distro QEMU binary or an unreviewed prebuilt image. A hand-written replacement Dockerfile would create another unvalidated recipe; defer it until a concrete upstream gap requires a reviewed overlay.

Before a later build is eligible:

1. Consume the verified cache read-only into a separate source/build workspace. Record all recipe/context hashes. The Docker build context is `emulator/docker/`; runtime source mounted at `/repo` is an additional identity, not baked into that image.
2. Resolve package versions/architectures and archive SHA-256 values from authenticated snapshot metadata. Retain InRelease/Release identities, signing-key provenance, the full installed package BOM, native compiler/build tools, cross compiler/binutils/sysroot, OpenSSL and SquashFS versions. The JSON recipe identity pins which package names to resolve; it does not claim this BOM exists.
3. Verify the source descriptor/signing chain and both QEMU source archives, including Debian patches, then apply only the recorded device patch. Record patch applicability and the final source identity. Preserve corresponding source and notices before distribution.
4. In a separately reviewed nonprivileged, firmware-free builder, build the fixed platform candidate with no host sockets, devices, credentials or personal paths. Restrict dependency network access to reviewed repositories; subsequent replay uses verified retained inputs. Record build frontend/BuildKit version, builder image/platform, configuration, environment and recipe identity. Do not give fetched build code a privileged daemon.
5. Record the final OCI manifest/config digest, full patched QEMU ELF SHA-256, toolchain/sysroot identity, each shim SHA-256, ABI/loader report and build logs. Pin actual results in a later reviewed artifact record. Never infer these hashes from source hashes or a local image tag.
6. Compare independent clean rebuilds. If outputs differ, retain both hashes and diagnose timestamps, paths, toolchain or other nondeterminism; source pinning alone does not prove bit reproducibility. Keep the candidate blocked until reproducibility or its precise limits are reviewed.

No build was attempted here. Existing Python `uv.lock` does not pin this C/Debian environment; the existing unpinned Hatchling build-backend issue remains a separate packaged-Lab-release gate.

The source-only projection is **not a complete runtime checkout**: setup imports excluded `firmware.profile`, extraction imports excluded tools, and default selection reads excluded `firmware/active-version`. Current scripts cannot run from the projection as it stands. M1-02 must review a narrow source-only dependency acquisition/overlay with exact file identities (including imports), or implement a reviewed Lab boundary. Do not silently widen `includePaths`, fetch every excluded blob or turn the source cache into a mutable working copy. Any approved projection expansion creates a separate cache identity and preserves the original.

## Local firmware identity and authenticity requirements

The [pinned profile](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/firmware/v2.57.json) declares product `SNOWSKY_DISC`, main `257`, recovery `18`, 77 rootfs chunks, reconstructed SquashFS size **80,596,992 bytes** and SHA-256 `111e4dd7ee3d7ff91ba7e61181690be7ffd22bd1bbd13ad513f5f015ffb302ae`. Its six reference hashes cover stock player, stock UI, BusyBox, loader, libc and tinyalsa. These are recorded verbatim as **upstream claims**, not local firmware observations or a Lab-approved authenticity chain. The rootfs hash identifies the reconstructed image, not an extracted directory tree. No full ZIP checksum is known from this review.

M1-02 should provide local selection only, with lawful user-supplied inputs and explicit operation consent. Before accepting a candidate, require:

- A bounded regular ZIP or OTA-directory input; reject unsafe links/reparse points, special files, traversal/absolute/drive paths, duplicate/case-colliding members, encrypted/nested archive surprises and unbounded entry counts, expansion, time or size. Choose and test concrete limits before intake ships. Directory traversal and later reads must recheck confinement and file identity; a prior path check is insufficient.
- Exact product/main/recovery metadata, bounded strict parsing and duplicate-field refusal. Require indices `0000..0076` exactly once, correct chunk-name grammar, no gaps/extras, consistent lengths and manifest membership, and encrypted-chunk SHA-256 checks. Do not treat MD5 or a hash embedded in a filename as authenticity. ZIP and selected folder, when both supplied, must agree.
- Hash the original package and metadata/manifest/signature bytes; retain a private input receipt before extraction. M1-02 intake is separate from M1-03 decryption/extraction. Chunk plaintext/rootfs and six original-binary verification occur only at the later extraction/static-verification boundary, with no guest execution. Missing or mismatched identities refuse promotion.
- Keep original bytes immutable and all generated/changed bytes separate. Unknown versions remain candidates, not aliases of V2.57. No automatic network fallback, version guessing, signature bypass or reuse of a failed run's rootfs.

The [upstream inventory tool](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/firmware/tools/firmware_inventory.py) checks integrity and explicitly does **not** authenticate the manifest signature. The [extractor](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/firmware/tools/firmware_extract.py) assembles/decrypts and checks rootfs size/hash before `unsquashfs`; it is not a complete archive safety or trust policy. A copied checksum manifest and the public decryption mechanism cannot establish vendor origin.

Vendor public-key provenance, trust-anchor fingerprint, signature format/algorithm, exact signed bytes and scope (rootfs chunks versus metadata/kernel/recovery), key rotation/revocation and failure handling remain unresolved. M1-02 may inventory known upstream-matching bytes while reporting `authenticity: unverified`. Executable use stays blocked until an independently reviewed vendor trust chain or an explicit owner-approved provenance policy defines the permitted alternative and records its limits. Neither a checkbox nor user consent alone may label bytes vendor-authenticated. No key, signing secret, download credential or proprietary byte belongs in public evidence.

## Baseline modifications and launch identity

The [key patch wrapper](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/scripts/patch_keys.sh) invokes the [profile implementation](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/firmware/profile.py). V2.57 modifies only the recorded key guard in `usr/bin/mq_player`: file offset `0xe7300`, VA `0x4e7300`, `41004292` → `01000224`. Upstream checks ELF32 LE MIPS, executable PT_LOAD address mapping and a whole-binary stock hash after normalizing this one site; it accepts its already-patched form for idempotence.

Lab intake must require original stock bytes. A later baseline-overlay step works on a fresh private copy, checks full input identity and expected original bytes, applies once and records the full resulting ELF hash. Already-patched inputs are not original firmware; a retry may reuse an output only with a matching owned transformation receipt. The patched-output hash remains null here because no firmware was handled. This is an emulator baseline key-enablement patch, not permission for UI-specific player modifications. Record `KEYS_ENABLE=1`; disabling it is a distinct scenario.

Future initial stock plan: explicit `FW_VERSION=2.57`, `BOOT_MODE=direct`, patched interpreter by full identity, `QEMU_DEVICES=1`, `PROC_EXE=0`, `FPU_GUARD=reject`, finite TTL, and no custom UI/watch loop. Stock-init and warm replacement remain separate deferred modes. The shim build, preload file, synthetic devices, battery/settings presets and original/final stock hashes all belong in the run receipt.

Track filesystem overlays separately from binary patches: `16_network.sh` replaces selected guest commands with `guest-command.sh`, retaining originals under `/emu/original-commands`; optional init boot also installs `guest-init-stub.sh` through `17_init_stubs.sh`. These changes persist in the work rootfs. Stop/down does not restore stock bytes, and no restore path was identified. The full overlay inventory must accompany any future execution receipt. `run.sh` can rewrite its local `.env`, and boot deletes prior PNG/SNAP captures: use separate writable configuration and per-run evidence paths, never the source cache or retained evidence directory.

**Setup is execution:** `10_setup_env.sh` compiles shims, registers binfmt, patches the player and starts stock UI/player to prime the settings database. `01_image_rootfs.sh`, `00_extract_rootfs.sh`, `run.sh up` and a Compose build/up are not metadata probes. None was run here. M1-02 must not call setup as an intake validator.

## Isolation, mounts, network and privileges

The [upstream Compose configuration](https://github.com/eudj1n/snowsky-disc-qemu/blob/85ab00deb08ac112066377fd8083cc8727ed859a/emulator/compose.yaml) is **not approved unchanged**: privileged emulator, shared guest networking by default, writable whole-repository mount, persistent work volume, loopback service ports and optional viewer/bridge. Upstream documents Docker Engine 28.1+ and Compose 2.36+; these minimums are not exact Lab runtime pins or evidence of Windows support. Exact host/kernel/WSL/Docker/Compose versions must be recorded at acceptance.

Initial trusted runtime strategy is a dedicated disposable Linux VM/Docker engine containing one serialized session. This may be a dedicated WSL2 environment only after its actual engine/kernel sharing is proven isolated from unrelated work; a distribution name, Compose project or separate volume alone does not establish that boundary. qemu-user shares the kernel; privileged Docker is not a sandbox for arbitrary binaries. Binfmt registrations and loop devices can affect the whole Docker VM.

| Boundary | Required later plan and refusal condition |
| --- | --- |
| Source/build | Verified source read-only; separate writable build/output area. No firmware, secrets or privileged daemon access in builds/public CI. |
| Firmware input | Only selected private input mounted read-only inside the dedicated VM. No host home, entire repository, personal media, credential directory, Docker socket or host `/dev` bind mount. |
| Work and media | Fresh owned run directory/volume per firmware and run ID; separate immutable original, extraction, overlays, userdata, virtual card, PCM/frame/log areas. Only generated media copied in. No shared mutable work volume or real block-device passthrough. |
| Process/IPC | Private container PID/IPC/mount namespaces and mqueue mount; stock names `/ui` and `/player` remain private. Direct mode needs the container boundary; it does not get stock-init's inner namespaces automatically. Track process/container start identity, not names alone. |
| Network | Container `network_mode: none` (or equivalent enforced isolation) plus isolated guest namespace for the initial local stock scenario. No published ports, viewer, bridge, LAN discovery or outbound access. Test the actual boundary; upstream command wrappers are not a firewall. A network scenario needs a separate explicit plan. |
| Privileges | Nonprivileged build/intake. Runtime privilege needs require review inside the disposable VM before launch; upstream keeps SYS_ADMIN for SD mounts despite dropping NET_ADMIN/SYS_TIME/SYS_BOOT/SYS_MODULE/SYS_RAWIO. Do not claim a proven reduced-capability recipe. No automatic privileged fallback on the normal host engine. |
| Limits | Establish CPU, memory, PID, disk/PCM/log quotas and bounded deadlines in the later runner. QEMU reserves large VA; do not substitute physical-device RAM limits. No unlimited TTL or restart policy. Partial cleanup blocks reuse. |

No executable Compose overlay is shipped: without runtime validation, such a file could imply an operational safe runner. Later review must prove namespace ownership, no host paths/devices/sockets, blocked egress, session-scoped stop, stale queue handling and failure cleanup before firmware execution. The ADR's readiness/stop budgets remain design values. Fixed sleeps, old pixels or a process name cannot establish stock readiness.

## Cleanup, retention and reporting

Before a later operation creates anything, write an ownership receipt with run ID, firmware/source/build tuple, canonical owned roots, host/VM/container identity and start times, intended mounts/loops/bindings and process ownership. Refuse existing destinations, unsafe links, active foreign state or ambiguous ownership. Lock the VM runtime for the operation; a PID alone cannot prove a stale lock.

Stop only the owned process tree/container; bounded TERM/KILL/reap then verify exit. Unmount deepest owned mounts and detach only loop backing files proven to belong to this run. Binfmt changes must remain inside the exclusive disposable VM; do not reset unrelated registrations or detach loops by shared path/name alone. Do not copy upstream `99_stop.sh`'s global viewer-name `pkill`. Its stop does not establish full resource cleanup. No wildcard `rm`, global `pkill`, `docker system prune`, `down -v`, or general cleanup command belongs in intake.

On interruption/failure retain and quarantine the exact work area and private diagnostics. Never auto-repair or reuse it. Cleanup requires ownership/containment/no-follow checks again at use time, no active processes/mounts, and a user-selected retention decision. If teardown is uncertain, quarantine the VM as well. Manual deletion targets only a verified literal owned directory, never a root, source snapshot, firmware store or redirected mount. This document requests no deletion.

Retain verified source snapshots and original firmware inputs by default; no automatic expiry or source-cache migration. Keep failed/successful run artifacts private until the owner chooses disposal after review. A future cleanup feature needs bounded ownership/race/interruption acceptance before adoption. Retain public input IDs, sanitized outcome/limitation records and license notices separately from proprietary state.

Public export remains explicit and allowlisted: reviewed source identities and checksums, sanitized command/result metadata, and generated synthetic media only where content rights are clear. Vendor UI screenshots can contain proprietary art and need review. Do not upload rootfs, ZIP/chunks, stock or patched ELF/shims bundled with firmware, userdata, personal media, raw logs, memory dumps, signing material, or full work/cache directories. Revalidate the selected path and content at export; hashes do not grant redistribution rights.

## Blockers and M1 follow-up gates

| Gate | Current evidence and required next step |
| --- | --- |
| Dependency/build identity | Base/index/platform digest, recipe/context hashes, dated repositories, QEMU version and descriptor archive checksums recorded. Resolve authenticated full package BOM and compiler/sysroot identity; build only under a separately reviewed recipe/environment. |
| Runtime outputs | Final image, QEMU executable, shim and patched-player hashes absent. They must be measured and recorded before any launch; repeat-build comparison NOT RUN. |
| Source availability | The independently pinned data-only V2.57 reference is consumed without widening the existing M0 source projection/cache. The upstream firmware parser/tooling remains excluded and is not imported or executed. |
| Firmware provenance | Upstream reference rootfs/six ELF identities known; no actual local archive hash or measurements and no authenticated vendor trust anchor. M1-02 defines bounded synthetic-tested intake/refusal behavior; M1-03 binds accepted structure to a private digest-checked snapshot. Neither establishes vendor authenticity. |
| Isolation/runtime | M1-03 implements local per-session staging, ownership checks, quotas, no-replace publication and quarantine. Dedicated VM, runtime privilege policy, guest mount/network acceptance and Windows WSL2/Docker acceptance remain NOT RUN. No safe launch recipe is claimed. |
| Licensing | Integration MIT evidence does not clear external QEMU/patch provenance, QEMU corresponding-source obligations, static library dependencies or Debian/toolchain redistribution notices. Review exact components before affected builds/distributions. Vendor rights and Lab root LICENSE/NOTICE remain unresolved; no license selected here. UI/font gates remain as in the existing inventory. |
| Compatibility | All stock boot/input/media/PCM/restart/concurrency/hardware scenarios NOT RUN. Keep combinations `unknown`; no emulator/device support promotion. |

**Current handoff:** M1-02's offline structural intake and M1-03's private snapshot foundation are implemented in the stacked Draft series and verified with synthetic samples only. M1-03 remains open because no extractor, decryptor, rootfs mount or extracted artifact exists. M1-04 boot and all runtime steps require their own reviewed gates; preparation completion does not authorize them. M1-01's evidence/preparation slice remains distinct from full runtime-pin acceptance, which stays open until the missing artifact identities and relevant build, licensing, provenance and isolation gates are closed.

## Preparation verification

Local Windows/Python 3.14 checks on this documentation-only change:

- `uv sync --locked --dev --offline` with repository-local `UV_CACHE_DIR`: passed.
- Ruff lint/format and `ty check`: passed; existing suite: **142 passed, 1 skipped**. The first restricted-sandbox run failed seven synthetic local-Git fetch cases; the full rerun outside that sandbox passed. No product fix or contract change was made to obtain that result.
- Actual CLI source verification and offline sync of all three existing projections, plus valid UI/firmware manifest validation: passed. Source IDs and runtime disclaimers retained.
- Independent recomputation of the source SHA-256/Git blob identities, comparison to the unchanged source lock and exact profile metadata, registry index digest comparison, JSON parse and local-link checks: passed. For excluded source evidence, retrieve only the named public files at the immutable commit and decode contents API base64 bytes before hashing; do not hash newline-normalized shell output. `firmware/active-version` is recorded as a separate public-source identity because `profile.py` reads it at import time.
- `git diff --check` and comparison against integrated main for `src/`, `schemas/`, `tests/`, `upstreams.lock.yaml`, dependency files and CI: unchanged/passed. The PR's hosted checks provide separate exact-head evidence.

No runtime/container/toolchain build, proprietary firmware access, extraction, decryption, QEMU invocation, external UI, physical device or performance test was performed. Metadata retrieval and local source hashing do not close those gates.
