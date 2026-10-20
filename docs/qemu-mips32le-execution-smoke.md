# Firmware-free MIPS32LE QEMU execution smoke

This check proves that the pinned, locally built `qemu-mipsel` user-mode
interpreter can run one first-party, statically linked MIPS32 little-endian O32
program. It does not boot a guest operating system or establish V2.57 firmware,
vendor authenticity, or device compatibility.

The branch-scoped GitHub Actions workflow reuses the M1-01 source projection,
Debian snapshot, signed source indexes, source archive hashes, licensing review,
base image digest, QEMU device patch, and shim build. It compiles the synthetic
C fixture with the pinned Debian MIPS cross toolchain. PR #13's matching second
clean build remains the reproducibility evidence for the unchanged QEMU and
shim build inputs; this workflow builds those outputs once and adds the guest
compile and execution checks afterward.

Only the temporary QEMU executable and guest ELF are copied out of the build
container. A separate container runs them with the same digest-pinned Debian
base image, `--network none`, a read-only root filesystem and input mount, UID
65534, all capabilities dropped, no-new-privileges, no explicit host device or
USB passthrough, a 256 MiB memory and swap limit, one CPU, a 16-process limit,
and a 32 MiB noexec temporary filesystem. The guest success and failure cases
have five-second deadlines; the deliberate busy-loop case has a two-second
deadline and a one-second forced-kill grace period. A 30-second host-side
deadline also bounds the complete runtime container.

The workflow summary contains a JSON receipt with the measured QEMU and guest
hashes, guest ELF class/endian/ABI, QEMU version output, deterministic stdout
digest, observed exit statuses, duration, runner and toolchain identities,
container isolation settings, and explicit verified and unverified
capabilities. Binaries exist only in temporary storage and are removed after
the job. The QEMU process runs only inside the runtime container; no binfmt
handler, firmware, stock binary, device, or guest operating system is used.
