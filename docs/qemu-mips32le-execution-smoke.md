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

The fixture is a static Linux MIPS O32 executable, matching QEMU 7.2's
documented `qemu-mipsel` user-mode target and avoiding a target dynamic loader.
If the success attempt exits unsuccessfully or produces different stdout, the
same fixed guest is retried once with `QEMU_STRACE=1`, a five-second deadline,
and the same container restrictions. QEMU syscall, guest-error, and instruction
logging is captured to the existing noexec temporary filesystem. The diagnostic
process has a 4 MiB file-size limit, and the workflow retains at most 4 KiB of
debug output plus 768 sanitized characters each of QEMU stdout and stderr. It
reports an error category, stdout byte count and digest.
Categories distinguish ELF loading, permissions, memory or address mapping,
syscall failure, QEMU process failure, and stdout mismatch. This diagnostic
retry does not increase the container's 256 MiB memory, one-CPU, 16-process, or
network restrictions. These behaviors follow the [QEMU 7.2 user-mode
documentation](https://qemu.googlesource.com/qemu/+/6f2ffa080f70c72db023283c487996efe188a911/docs/user/main.rst).

The workflow summary contains a JSON receipt with the measured QEMU and guest
hashes, guest ELF class/endian/ABI, QEMU version output, deterministic stdout
digest, observed exit statuses, duration, runner and toolchain identities,
container isolation settings, and explicit verified and unverified
capabilities. Binaries exist only in temporary storage and are removed after
the job. The QEMU process runs only inside the runtime container; no binfmt
handler, firmware, stock binary, device, or guest operating system is used.
