# M2-02 offline UI binary preflight

`preflight_ui_binary` inspects a locally selected ELF as data and compares its
metadata with two explicit, versioned caller-supplied contracts. It never loads
or modifies the binary, invokes a runner, accesses firmware, or authorizes a
launch. Its `launchAuthorized` value is always `false`.

The existing [bounded ELF inspector](elf-inspection.md) performs the read,
SHA-256, size, ELF structure, MIPS ABI, floating-point ABI, interpreter, and
`DT_NEEDED` parsing. The preflight applies the narrow M2-02 policy: executable
ELF32, little-endian MIPS, O32 ABI, explicit soft/hard float metadata, and
conclusive static/dynamic linkage. A known mismatch is `BLOCKED`; incomplete
evidence is `UNKNOWN`. `STATIC_MATCH` means only that these static checks and
the supplied target assertions agree. It is not a compatibility state in the
registry and proves nothing about firmware boot, IPC, runtime dependencies,
QEMU, or hardware.

The [path declaration](../schemas/lab-ui-binary-paths-v1.schema.json) binds
reviewed `requiredPaths` to the exact binary SHA-256. It is the sole source of
required filesystem paths. Arbitrary printable strings in the ELF are never
promoted to requirements. A missing declaration is `UNKNOWN`; a stale digest
is `BLOCKED`. Paths must be canonical absolute guest paths. Callers must
independently review the origin of each declared path.

The [target contract](../schemas/lab-ui-binary-target-v1.schema.json) names
one exact binary digest, runner and profile identifiers, expected ABI, float
mode, linkage, interpreter, reviewed dependency names, and declared available
or absent guest paths. It is an **assertion**, not an authenticated inventory
or a runner probe. A missing contract is `UNKNOWN`. Its names do not verify
library bytes: any `DT_NEEDED` dependency remains `dependencies-unverified`
and prevents `STATIC_MATCH`, even if its name appears in
`reviewedDependencies`. A declared available interpreter/path is only a
reviewed assertion; known absence blocks, and undeclared presence stays
unknown. Contracts reject extra fields, duplicate list entries, contradictory
path inventories, noncanonical paths, and invalid identifiers.

Example use with decoded Python dictionaries:

```python
from snowsky_disc_lab.ui_binary_preflight import preflight_ui_binary

report = preflight_ui_binary(
    local_binary,
    target=reviewed_target,
    paths=reviewed_path_declaration,
)
```

The report has `apiVersion: lab-ui-binary-preflight/v1`, `status`, stable
sorted `reasons`, ELF inspection metadata, reviewed `requiredPaths`, target
runner/profile IDs, and `launchAuthorized: false`. It does not accept JSON
files directly. A future JSON loader must enforce bounded reads and reject
duplicate keys. Input contracts are revalidated even if a mutable Pydantic
model is passed. Parse errors are sanitized by field name and do not echo
untrusted strings.

The ELF parser conservatively reports many float modes, absent ABI flags,
ambiguous linkage, and unknown ABI values as `UNKNOWN`. This comparison does
not prove MIPS ISA revision, FP64/NaN mode, symbol availability, library
contents, guest path existence, protocol compatibility, or runner/profile
provenance. ET_DYN executables are currently blocked as a conservative file
type limitation. A future trusted runtime preflight must verify exact
dependency bytes and the exact profile/runner before execution.
