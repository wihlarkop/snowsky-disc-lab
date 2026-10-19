"""Pinned, partial Git source cache with a read-only projected worktree."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, BinaryIO

if TYPE_CHECKING:
    from snowsky_disc_lab.source_lock import SourcePin


_REPOSITORY = re.compile(
    r"^https://github\.com/[A-Za-z0-9][A-Za-z0-9-]*/"
    r"[A-Za-z0-9][A-Za-z0-9._-]*\.git$"
)
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_TREE_PATH_BYTES = 4096
DEFAULT_CACHE_DIR = ".lab/sources"


def source_cache_root(lock: Path, cache_dir: str = DEFAULT_CACHE_DIR) -> Path:
    """Resolve the shared CLI cache setting without loading a lock or creating paths."""
    if (
        not cache_dir
        or re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", cache_dir) is None
        or any(
            part.rstrip(" .") in {"", ".", "..", ".git"} for part in cache_dir.lower().split("/")
        )
    ):
        raise ValueError(
            "Cache directory must be a safe relative POSIX path within the lock folder."
        )
    return lock.absolute().parent / cache_dir


class SourceError(ValueError):
    """A pinned source could not be safely verified or cached."""


class _TreeEntry:
    __slots__ = ("mode", "kind", "oid", "path")

    def __init__(self, mode: str, kind: str, oid: str, path: str) -> None:
        self.mode = mode
        self.kind = kind
        self.oid = oid
        self.path = path


def _validate_pin(pin: SourcePin) -> None:
    try:
        source_id = pin.id
        repository = pin.repository
        commit = pin.commit
        include_paths = pin.include_paths
        licenses = pin.licenses
    except AttributeError:
        raise SourceError("Source pin is incomplete; reload the validated upstream lock.") from None

    if (
        not isinstance(source_id, str)
        or not re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", source_id)
        or _unsafe_windows_name(source_id)
    ):
        raise SourceError(
            "Source pin has an invalid identifier; reload the validated upstream lock."
        )
    if not isinstance(repository, str) or not _REPOSITORY.fullmatch(repository):
        raise SourceError(
            "Source repository must be a canonical HTTPS github.com/owner/repo.git URL."
        )
    if not isinstance(commit, str) or not _COMMIT.fullmatch(commit):
        raise SourceError("Source commit must be an exact lowercase 40-character Git SHA-1.")
    if not isinstance(include_paths, list) or not include_paths:
        raise SourceError("Source pin must declare a non-empty path projection.")
    if not isinstance(licenses, list) or not licenses:
        raise SourceError("Source pin must declare at least one license record.")
    for value in include_paths:
        if not isinstance(value, str):
            raise SourceError("Source projection contains an invalid path.")
        _validate_projection_path(value)
    for record in licenses:
        if not isinstance(record.path, str) or not isinstance(record.sha256, str):
            raise SourceError("Source pin contains an invalid license record.")
        _validate_projection_path(record.path)
        if record.path.endswith("/") or not _SHA256.fullmatch(record.sha256):
            raise SourceError("Source pin contains an invalid license path or SHA-256.")


def _validate_projection_path(value: str) -> None:
    directory = value.endswith("/")
    raw = value[:-1] if directory else value
    if not raw or "\\" in raw or ":" in raw or raw.startswith("/"):
        raise SourceError("Source projection paths must be safe relative POSIX paths.")
    if len(raw.encode("utf-8")) > _MAX_TREE_PATH_BYTES:
        raise SourceError("Source projection path exceeds Git's supported path length.")
    parts = raw.split("/")
    if any(part in {"", ".", ".."} or _unsafe_windows_name(part) for part in parts):
        raise SourceError("Source projection paths must not contain unsafe path components.")
    if any(part.casefold() == ".git" for part in parts):
        raise SourceError("Source projection cannot include Git metadata paths.")


def _unsafe_windows_name(name: str) -> bool:
    if name.endswith((".", " ")) or any(ord(char) < 32 or ord(char) == 127 for char in name):
        return True
    stem = name.partition(".")[0].upper()
    return stem in {"CON", "PRN", "AUX", "NUL"} or bool(re.fullmatch(r"(?:COM|LPT)[1-9]", stem))


def _projection_fingerprint(pin: SourcePin) -> str:
    canonical = json.dumps(sorted(pin.include_paths), ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()[:32]


def source_path(root: Path, pin: SourcePin) -> Path:
    """Return the immutable cache path for this commit and exact projection."""
    _validate_pin(pin)
    absolute_root = Path(os.path.abspath(os.fspath(root)))
    if any(part.rstrip(" .").casefold() == ".git" for part in absolute_root.parts):
        raise SourceError("Source caches cannot be placed inside Git metadata directories.")
    _check_components(absolute_root, allow_missing_leaf=True)
    projection = _projection_fingerprint(pin)
    return absolute_root / pin.id / f"{pin.commit}-{projection}"


def _is_reparse_point(path: Path) -> bool:
    try:
        entry = path.lstat()
    except FileNotFoundError:
        return False
    attributes = getattr(entry, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(entry.st_mode) or bool(attributes & reparse)


def _check_components(path: Path, *, allow_missing_leaf: bool = False) -> None:
    """Refuse symlinks and Windows reparse points in every path component."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    components = list(reversed((absolute, *absolute.parents)))
    for index, component in enumerate(components):
        if not os.path.lexists(component):
            if allow_missing_leaf:
                continue
            raise SourceError("Source cache path is missing; sync the locked source first.")
        if _is_reparse_point(component):
            raise SourceError(
                "Source cache path contains a symlink or junction; inspect it manually."
            )
        try:
            status = component.lstat()
        except OSError:
            raise SourceError("Source cache path cannot be inspected safely.") from None
        if index < len(components) - 1 and not stat.S_ISDIR(status.st_mode):
            raise SourceError("Source cache path has a non-directory parent component.")


def _git_environment(*, lazy_fetch: bool) -> dict[str, str]:
    environment = os.environ.copy()
    for key in tuple(environment):
        if key.upper().startswith("GIT_"):
            environment.pop(key, None)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    if not lazy_fetch:
        environment["GIT_NO_LAZY_FETCH"] = "1"
    return environment


def _git(
    repository: Path,
    *arguments: str,
    lazy_fetch: bool = False,
    input_bytes: bytes | None = None,
    trace_packets: bool = False,
    allow_file_protocol: bool = False,
) -> bytes:
    hooks_path = repository / ".git" / "lab-no-hooks"
    command = [
        "git",
        "-c",
        f"core.hooksPath={hooks_path}",
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.attributesFile={os.devnull}",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.allow=never",
        "-c",
        f"protocol.https.allow={'always' if lazy_fetch else 'never'}",
        "-c",
        f"protocol.file.allow={'always' if allow_file_protocol else 'never'}",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "http.followRedirects=false",
        "-c",
        "http.sslVerify=true",
        "-c",
        "submodule.recurse=false",
        "-C",
        os.fspath(repository),
        *arguments,
    ]
    environment = _git_environment(lazy_fetch=lazy_fetch)
    environment["GIT_CEILING_DIRECTORIES"] = os.fspath(repository.parent)
    if trace_packets:
        environment["GIT_TRACE_PACKET"] = "1"
    try:
        result = subprocess.run(
            command,
            input=input_bytes,
            capture_output=True,
            env=environment,
            check=False,
            timeout=180 if "fetch" in arguments else 60,
        )
    except subprocess.TimeoutExpired:
        raise SourceError(
            "Git timed out while verifying the pinned source; retry after checking connectivity."
        ) from None
    except OSError:
        raise SourceError(
            "Git could not be started; install Git and retry the source sync."
        ) from None
    if result.returncode != 0:
        action = arguments[0] if arguments and re.fullmatch(r"[a-z-]+", arguments[0]) else "command"
        raise SourceError(
            f"Git {action} failed with status {result.returncode}; inspect the cache and retry."
        )
    return result.stdout


def _config_values(config_path: Path) -> dict[str, str]:
    if _is_reparse_point(config_path):
        raise SourceError(
            "Source Git configuration is a symlink or reparse point; inspect the cache."
        )
    try:
        metadata = config_path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 64 * 1024:
            raise SourceError(
                "Source Git configuration is not a bounded regular file; inspect the cache."
            )
        raw = config_path.read_bytes()
    except SourceError:
        raise
    except OSError:
        raise SourceError(
            "Source Git configuration is missing or unreadable; inspect the cache."
        ) from None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise SourceError("Source Git configuration is malformed; inspect the cache.") from None

    section = ""
    values: dict[str, str] = {}
    for source_line in text.splitlines():
        line = source_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        section_match = re.fullmatch(r'\[([A-Za-z][A-Za-z0-9]*)\s*(?:"([^"]+)")?\]', line)
        if section_match:
            section_name = section_match.group(1).lower()
            subsection = section_match.group(2)
            section = f"{section_name}.{subsection.lower()}" if subsection else section_name
            continue
        item_match = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*?)\s*", line)
        if item_match and section:
            key = f"{section}.{item_match.group(1).lower()}"
            if key in values:
                raise SourceError("Source Git configuration has duplicate keys; inspect the cache.")
            values[key] = item_match.group(2)
            continue
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", line) and section:
            key = f"{section}.{line.lower()}"
            if key in values:
                raise SourceError("Source Git configuration has duplicate keys; inspect the cache.")
            values[key] = "true"
            continue
        raise SourceError("Source Git configuration is malformed; inspect the cache.")
    return values


def _check_git_config(path: Path, pin: SourcePin) -> None:
    config = _config_values(path / ".git" / "config")
    allowed = {
        "core.repositoryformatversion",
        "core.filemode",
        "core.bare",
        "core.logallrefupdates",
        "core.ignorecase",
        "core.symlinks",
        "core.sparsecheckout",
        "core.sparsecheckoutcone",
        "core.longpaths",
        "core.autocrlf",
        "core.fsmonitor",
        "core.attributesfile",
        "remote.origin.url",
        "remote.origin.promisor",
        "remote.origin.partialclonefilter",
        "extensions.partialclone",
    }
    if not set(config).issubset(allowed):
        raise SourceError(
            "Source Git configuration contains unexpected settings; inspect the cache."
        )
    expected = {
        "core.repositoryformatversion": "1",
        "core.bare": "false",
        "core.sparsecheckout": "true",
        "core.sparsecheckoutcone": "false",
        "core.longpaths": "true" if os.name == "nt" else "false",
        "core.autocrlf": "false",
        "core.fsmonitor": "false",
        "core.attributesfile": os.devnull,
        "remote.origin.url": pin.repository,
        "remote.origin.promisor": "true",
        "remote.origin.partialclonefilter": "blob:none",
        "extensions.partialclone": "origin",
    }
    if any(config.get(key) != value for key, value in expected.items()):
        raise SourceError("Source Git configuration does not match the pinned partial clone.")
    controlled = {
        "core.ignorecase": "true" if os.name == "nt" else "false",
        "core.symlinks": "true",
        "core.filemode": "false" if os.name == "nt" else "true",
    }
    if any(config.get(key) != value for key, value in controlled.items()):
        raise SourceError("Source Git configuration has unsafe file mode settings.")


def _check_metadata_tree(path: Path) -> None:
    git_dir = path / ".git"
    if _is_reparse_point(git_dir):
        raise SourceError(
            "Source cache must contain a real .git directory, not a worktree or symlink."
        )
    try:
        status = git_dir.lstat()
    except OSError:
        raise SourceError(
            "Source cache is not a complete Git checkout; sync the locked source."
        ) from None
    if not stat.S_ISDIR(status.st_mode):
        raise SourceError(
            "Source cache must contain a real .git directory, not a worktree or symlink."
        )
    for directory, child_dirs, files in os.walk(git_dir, followlinks=False):
        parent = Path(directory)
        for name in [*child_dirs, *files]:
            component = parent / name
            if _is_reparse_point(component):
                raise SourceError(
                    "Source Git metadata contains a symlink or junction; inspect the cache."
                )
            try:
                entry = component.lstat()
            except OSError:
                raise SourceError(
                    "Source Git metadata changed while it was being verified."
                ) from None
            if name in child_dirs and stat.S_ISDIR(entry.st_mode):
                continue
            if not stat.S_ISREG(entry.st_mode):
                raise SourceError("Source Git metadata contains a special file; inspect the cache.")
        child_dirs[:] = [name for name in child_dirs if not _is_reparse_point(parent / name)]
    for unexpected in (
        git_dir / "objects" / "info" / "alternates",
        git_dir / "objects" / "info" / "http-alternates",
        git_dir / "commondir",
        git_dir / "info" / "grafts",
        git_dir / "lab-no-hooks",
    ):
        if os.path.lexists(unexpected):
            raise SourceError(
                "Source Git metadata contains an alternate or hook path; inspect the cache."
            )
    attributes = git_dir / "info" / "attributes"
    if attributes.exists():
        try:
            attr_status = attributes.lstat()
            if not stat.S_ISREG(attr_status.st_mode) or attr_status.st_size > 64 * 1024:
                raise SourceError("Source Git local attributes are not a bounded regular file.")
            if attributes.read_bytes():
                raise SourceError(
                    "Source Git metadata contains unexpected local attribute filters."
                )
        except SourceError:
            raise
        except OSError:
            raise SourceError(
                "Source Git local attributes could not be inspected safely."
            ) from None
    replace_refs = git_dir / "refs" / "replace"
    if replace_refs.exists() and any(replace_refs.iterdir()):
        raise SourceError("Source Git metadata contains replace refs; inspect the cache.")


def _tree_entries(path: Path, pin: SourcePin) -> list[_TreeEntry]:
    output = _git(path, "ls-tree", "-r", "--full-tree", "-z", pin.commit)
    entries: list[_TreeEntry] = []
    seen_casefolded: set[str] = set()
    for record in output.split(b"\0"):
        if not record:
            continue
        header, separator, path_bytes = record.partition(b"\t")
        if not separator or len(path_bytes) > _MAX_TREE_PATH_BYTES:
            raise SourceError("Pinned source tree contains a malformed or oversized path.")
        try:
            mode, kind, oid = header.decode("ascii").split(" ")
            name = path_bytes.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            raise SourceError(
                "Pinned source tree contains a non-portable path or object entry."
            ) from None
        _validate_tree_path(name)
        folded = name.casefold()
        if folded in seen_casefolded:
            raise SourceError("Pinned source tree has paths that collide on Windows filesystems.")
        seen_casefolded.add(folded)
        if not re.fullmatch(r"[0-9a-f]{40}", oid):
            raise SourceError("Pinned source tree contains an invalid Git object identity.")
        entries.append(_TreeEntry(mode, kind, oid, name))
    return entries


def _validate_tree_path(value: str) -> None:
    if not value or "\\" in value or ":" in value or value.startswith("/"):
        raise SourceError(
            "Pinned source tree contains an unsafe path; inspect the reviewed source pin."
        )
    parts = value.split("/")
    if any(part in {"", ".", ".."} or _unsafe_windows_name(part) for part in parts):
        raise SourceError(
            "Pinned source tree contains an unsafe path; inspect the reviewed source pin."
        )
    if any(part.casefold() == ".git" for part in parts):
        raise SourceError(
            "Pinned source tree contains a Git metadata path; inspect the reviewed pin."
        )


def _matches_projection(path: str, include_paths: list[str]) -> bool:
    for include in include_paths:
        if include.endswith("/"):
            if path.startswith(include):
                return True
        elif path == include:
            return True
    return False


def _selected_entries(entries: list[_TreeEntry], pin: SourcePin) -> list[_TreeEntry]:
    selected: list[_TreeEntry] = []
    for include in pin.include_paths:
        matching = [entry for entry in entries if _matches_projection(entry.path, [include])]
        if not matching:
            raise SourceError("A locked source projection path is absent from the pinned commit.")
    selected = [entry for entry in entries if _matches_projection(entry.path, pin.include_paths)]
    by_path = {entry.path: entry for entry in entries}
    for license_record in pin.licenses:
        entry = by_path.get(license_record.path)
        if entry is None or entry.kind != "blob" or entry.mode not in {"100644", "100755"}:
            raise SourceError("A locked license file is missing or is not a regular tracked file.")
    for entry in selected:
        if entry.kind != "blob" or entry.mode not in {"100644", "100755"}:
            raise SourceError("Selected source contains an unsupported file or submodule entry.")
        components = entry.path.split("/")
        if entry.path.lower().endswith((".bin", ".img", ".zip", ".iso")) or (
            len(components) >= 2
            and components[0].lower() == "flash"
            and entry.path.lower().endswith((".bin", ".img"))
        ):
            raise SourceError(
                "The locked projection includes a firmware or binary payload; narrow its paths."
            )
    return selected


def _sparse_patterns(pin: SourcePin) -> bytes:
    patterns: list[str] = []
    for value in sorted(pin.include_paths):
        patterns.append(f"/{value}" if value.endswith("/") else f"/{value}")
    return ("\n".join(patterns) + "\n").encode("ascii")


def _validate_sparse_file(path: Path, pin: SourcePin) -> None:
    info = path / ".git" / "info"
    if _is_reparse_point(info) or not info.is_dir():
        raise SourceError("Source sparse-checkout metadata is missing or unsafe.")
    sparse = info / "sparse-checkout"
    if _is_reparse_point(sparse):
        raise SourceError("Source sparse-checkout metadata is a symlink or reparse point.")
    try:
        sparse_status = sparse.lstat()
        if not stat.S_ISREG(sparse_status.st_mode) or sparse_status.st_size > 64 * 1024:
            raise SourceError("Source sparse-checkout metadata is not a bounded regular file.")
        contents = sparse.read_bytes()
    except SourceError:
        raise
    except OSError:
        raise SourceError("Source sparse-checkout metadata is missing or unreadable.") from None
    if contents != _sparse_patterns(pin):
        raise SourceError("Source sparse-checkout paths do not match the locked projection.")
    exclude = info / "exclude"
    if exclude.exists():
        try:
            exclude_status = exclude.lstat()
            if not stat.S_ISREG(exclude_status.st_mode) or exclude_status.st_size > 64 * 1024:
                raise SourceError("Source Git exclude rules are not a bounded regular file.")
            text = exclude.read_text(encoding="utf-8")
        except SourceError:
            raise
        except (OSError, UnicodeDecodeError):
            raise SourceError(
                "Source Git exclude rules are unreadable; inspect the cache."
            ) from None
        meaningful = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if meaningful:
            raise SourceError("Source Git exclude rules are unexpected; inspect the cache.")


def _index_entries(path: Path) -> tuple[dict[str, tuple[str, str]], dict[str, str]]:
    staged = _git(path, "ls-files", "--stage", "-z")
    indexed: dict[str, tuple[str, str]] = {}
    for record in staged.split(b"\0"):
        if not record:
            continue
        header, separator, raw_path = record.partition(b"\t")
        if not separator:
            raise SourceError("Source Git index is malformed; inspect the cache.")
        try:
            mode, oid, stage = header.decode("ascii").split(" ")
            name = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            raise SourceError("Source Git index contains a non-portable path.") from None
        if stage != "0" or name in indexed:
            raise SourceError("Source Git index has an unresolved or duplicate entry.")
        indexed[name] = (mode, oid)

    flags_output = _git(path, "ls-files", "-v", "-z")
    flags: dict[str, str] = {}
    for record in flags_output.split(b"\0"):
        if not record:
            continue
        flag, separator, raw_path = record.partition(b" ")
        if not separator:
            raise SourceError("Source Git index flags are malformed; inspect the cache.")
        try:
            name = raw_path.decode("utf-8")
            tag = flag.decode("ascii")
        except UnicodeDecodeError:
            raise SourceError("Source Git index contains a non-portable path.") from None
        flags[name] = tag
    return indexed, flags


def _expected_directories(file_paths: set[str]) -> set[str]:
    directories: set[str] = set()
    for name in file_paths:
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            directories.add(str(parent))
            parent = parent.parent
    return directories


def _working_tree_paths(path: Path) -> tuple[set[str], set[str], dict[str, Path]]:
    files: set[str] = set()
    directories: set[str] = set()
    actual: dict[str, Path] = {}
    for current, child_dirs, child_files in os.walk(path, topdown=True, followlinks=False):
        parent = Path(current)
        relative_parent = parent.relative_to(path)
        if relative_parent == Path("."):
            child_dirs[:] = [name for name in child_dirs if name != ".git"]
        for name in [*child_dirs, *child_files]:
            item = parent / name
            relative = item.relative_to(path).as_posix()
            if name == ".git" and relative_parent == Path("."):
                if _is_reparse_point(item) or not item.is_dir():
                    raise SourceError("Source cache .git entry is not a real metadata directory.")
                continue
            _validate_tree_path(relative)
            if _is_reparse_point(item):
                raise SourceError(
                    "Source worktree contains a symlink or junction; inspect the cache."
                )
            try:
                item_status = item.lstat()
            except OSError:
                raise SourceError("Source worktree changed while it was being verified.") from None
            if stat.S_ISDIR(item_status.st_mode):
                directories.add(relative)
            elif stat.S_ISREG(item_status.st_mode):
                files.add(relative)
                actual[relative] = item
            else:
                raise SourceError("Source worktree contains a special file; inspect the cache.")
    return files, directories, actual


def _blob_hash(stream: BinaryIO) -> tuple[str, str, int]:
    try:
        size = stream.seek(0, os.SEEK_END)
        stream.seek(0)
    except (OSError, AttributeError):
        raise SourceError("Tracked source bytes could not be measured safely.") from None
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    sha1.update(f"blob {size}\0".encode("ascii"))
    while chunk := stream.read(1024 * 1024):
        sha1.update(chunk)
        sha256.update(chunk)
    return sha1.hexdigest(), sha256.hexdigest(), size


def _blob_hash_path(path: Path) -> tuple[str, str, int]:
    try:
        with path.open("rb") as stream:
            return _blob_hash(stream)
    except SourceError:
        raise
    except OSError:
        raise SourceError(
            "A tracked source file is missing or unreadable; inspect the cache."
        ) from None


def _verify_contents(path: Path, pin: SourcePin, entries: list[_TreeEntry]) -> None:
    selected = _selected_entries(entries, pin)
    expected = {entry.path: entry for entry in selected}
    object_ids = [entry.oid for entry in selected]
    if object_ids:
        output = _git(
            path,
            "cat-file",
            "--batch-check=%(objectname) %(objecttype)",
            input_bytes=("\n".join(object_ids) + "\n").encode("ascii"),
        )
        object_records = output.decode("ascii", errors="replace").splitlines()
        if len(object_records) != len(object_ids) or any(
            record.split() != [oid, "blob"]
            for record, oid in zip(object_records, object_ids, strict=False)
        ):
            raise SourceError(
                "A selected Git blob object is missing or corrupt in the offline cache."
            )
    indexed, flags = _index_entries(path)
    tree = {entry.path: entry for entry in entries}
    if set(indexed) != set(tree):
        raise SourceError("Source Git index does not match the pinned commit tree.")
    for name, entry in tree.items():
        if indexed[name] != (entry.mode, entry.oid):
            raise SourceError("Source Git index differs from the pinned commit tree.")
        flag = flags.get(name)
        if name in expected and flag != "H":
            raise SourceError("A selected source path has skip-worktree or assume-unchanged state.")
        if name not in expected and flag != "S":
            raise SourceError("An excluded source path is not safely marked skip-worktree.")
    if set(flags) != set(tree):
        raise SourceError("Source Git index flags do not match the pinned commit tree.")

    files, directories, actual = _working_tree_paths(path)
    expected_files = set(expected)
    if files != expected_files or directories != _expected_directories(expected_files):
        raise SourceError(
            "Source worktree contains missing or unexpected files; inspect the cache."
        )

    licenses = {license_record.path: license_record.sha256 for license_record in pin.licenses}
    for name, entry in expected.items():
        file_path = actual[name]
        actual_oid, actual_sha256, _ = _blob_hash_path(file_path)
        if actual_oid != entry.oid:
            raise SourceError("Tracked source content does not match its committed Git blob hash.")
        expected_license_hash = licenses.get(name)
        if expected_license_hash is not None and actual_sha256 != expected_license_hash:
            raise SourceError("A locked license file does not match its SHA-256 record.")

    status = _git(
        path,
        "status",
        "--porcelain=v2",
        "--untracked-files=all",
        "--ignored=matching",
        "--no-renames",
    )
    if status:
        raise SourceError("Source cache is dirty or contains ignored files; inspect the cache.")


def _verify_entry(path: Path, pin: SourcePin) -> Path:
    _check_components(path)
    _check_metadata_tree(path)
    _check_git_config(path, pin)
    _validate_sparse_file(path, pin)
    shallow = path / ".git" / "shallow"
    try:
        shallow_status = shallow.lstat()
        if not stat.S_ISREG(shallow_status.st_mode) or shallow_status.st_size > 4096:
            raise SourceError("Source shallow boundary is missing or invalid.")
        if shallow.read_text(encoding="ascii").splitlines() != [pin.commit]:
            raise SourceError("Source cache does not contain only the exact shallow commit.")
    except SourceError:
        raise
    except (OSError, UnicodeDecodeError):
        raise SourceError("Source shallow boundary is missing or invalid.") from None
    try:
        head = (path / ".git" / "HEAD").read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        raise SourceError(
            "Source cache HEAD is missing or unreadable; inspect the cache."
        ) from None
    if head != pin.commit:
        raise SourceError("Source cache is not detached at the exact locked commit.")
    if _git(path, "rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip() != pin.commit:
        raise SourceError("Source cache resolves to a different commit than the lock.")
    entries = _tree_entries(path, pin)
    _verify_contents(path, pin, entries)
    _git(path, "fsck", "--full", "--strict", "--no-reflogs", "--no-progress")
    return path


def verify_source(pin: SourcePin, cache_root: Path) -> Path:
    """Verify a complete pinned projection without network access or cache repair."""
    _validate_pin(pin)
    location = source_path(cache_root, pin)
    try:
        _check_components(location)
        return _verify_entry(location, pin)
    except SourceError:
        raise
    except (OSError, UnicodeDecodeError, subprocess.SubprocessError):
        raise SourceError(
            "Pinned source cache could not be verified; inspect it and sync again."
        ) from None


def _supports_filter(repository_path: Path, pin: SourcePin) -> None:
    environment = _git_environment(lazy_fetch=True)
    environment["GIT_CEILING_DIRECTORIES"] = os.fspath(repository_path.parent)
    environment["GIT_TRACE_PACKET"] = "1"
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                os.fspath(repository_path),
                "-c",
                "protocol.version=2",
                "-c",
                "credential.helper=",
                "-c",
                "http.followRedirects=false",
                "-c",
                "http.sslVerify=true",
                "ls-remote",
                "--refs",
                pin.repository,
                pin.commit,
            ],
            capture_output=True,
            env=environment,
            check=False,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        raise SourceError(
            "Git timed out while checking partial-clone support; retry later."
        ) from None
    except OSError:
        raise SourceError("Git could not inspect the pinned source server capabilities.") from None
    if result.returncode != 0:
        raise SourceError("Pinned source server did not allow a safe capability check.")
    trace = result.stderr.lower()
    if not re.search(rb"\bfetch=[^\r\n]*\bfilter\b", trace):
        raise SourceError(
            "Pinned source server lacks partial-clone filtering; refusing a full download."
        )


def _fetch_source(
    staging: Path,
    pin: SourcePin,
    *,
    fetch_url: str | None = None,
    preflight: bool = True,
    allow_file_protocol: bool = False,
) -> None:
    remote_url = fetch_url or pin.repository
    template = staging / ".empty-git-template"
    template.mkdir()
    try:
        _git(
            staging,
            "init",
            "--quiet",
            "--object-format=sha1",
            f"--template={template}",
        )
    finally:
        template.rmdir()
    _git(staging, "remote", "add", "origin", remote_url)
    for key, value in (
        ("core.repositoryformatversion", "1"),
        ("extensions.partialClone", "origin"),
        ("remote.origin.promisor", "true"),
        ("remote.origin.partialclonefilter", "blob:none"),
        ("core.sparseCheckout", "true"),
        ("core.sparseCheckoutCone", "false"),
        ("core.longpaths", "true" if os.name == "nt" else "false"),
        ("core.autocrlf", "false"),
        ("core.fsmonitor", "false"),
        ("core.attributesFile", os.devnull),
        ("core.ignorecase", "true" if os.name == "nt" else "false"),
        ("core.symlinks", "true"),
        ("core.filemode", "false" if os.name == "nt" else "true"),
    ):
        _git(staging, "config", "--local", key, value)
    _git(staging, "config", "--local", "--unset-all", "remote.origin.fetch")
    if preflight:
        _supports_filter(staging, pin)
    _git(
        staging,
        "fetch",
        "--filter=blob:none",
        "--depth=1",
        "--no-tags",
        "origin",
        pin.commit,
        lazy_fetch=True,
        allow_file_protocol=allow_file_protocol,
    )
    fetched = _git(staging, "rev-parse", "--verify", "FETCH_HEAD^{commit}").decode("ascii").strip()
    if fetched != pin.commit:
        raise SourceError("Git fetched a different object than the locked source commit.")
    if remote_url != pin.repository:
        _git(staging, "remote", "set-url", "origin", pin.repository)


def _prepare_projection(staging: Path, pin: SourcePin) -> list[_TreeEntry]:
    entries = _tree_entries(staging, pin)
    selected = _selected_entries(entries, pin)
    info = staging / ".git" / "info"
    info.mkdir(exist_ok=True)
    (info / "sparse-checkout").write_bytes(_sparse_patterns(pin))
    (info / "exclude").write_text("# source manager: no exclusions\n", encoding="utf-8")
    _git(
        staging,
        "checkout",
        "--detach",
        "--no-recurse-submodules",
        pin.commit,
        lazy_fetch=True,
    )
    return selected


def _ensure_directory(path: Path) -> None:
    _check_components(path, allow_missing_leaf=True)
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError:
        raise SourceError("Source cache directory could not be created safely.") from None
    _check_components(path)
    if not path.is_dir():
        raise SourceError("Source cache path is not a directory.")


def _create_lock(cache_root: Path, pin: SourcePin, projection: str) -> Path:
    lock_dir = cache_root / ".locks"
    _ensure_directory(lock_dir)
    lock_path = lock_dir / f"{pin.id}-{pin.commit}-{projection}.lock"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except FileExistsError:
        raise SourceError(
            "This pinned source is already syncing or has a stale lock; inspect .locks and retry."
        ) from None
    except OSError:
        raise SourceError("Source sync lock could not be created safely.") from None
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
    finally:
        os.close(descriptor)
    return lock_path


def _make_read_only(path: Path, selected: list[_TreeEntry]) -> None:
    for entry in selected:
        file_path = path.joinpath(*entry.path.split("/"))
        if file_path.is_symlink():
            continue
        try:
            current = file_path.stat().st_mode
            file_path.chmod(current & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        except OSError:
            raise SourceError("Cached source files could not be marked read-only.") from None


def _publish_no_replace(staging: Path, final_path: Path) -> None:
    if os.name == "nt":
        if os.path.lexists(final_path):
            raise FileExistsError
        os.rename(staging, final_path)
        return
    if not sys.platform.startswith("linux"):
        raise SourceError("Atomic no-replace publication is unsupported on this platform.")
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except (AttributeError, OSError):
        raise SourceError(
            "Atomic no-replace publication is unavailable on this Linux system."
        ) from None
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(staging),
        -100,
        os.fsencode(final_path),
        1,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise FileExistsError(error_number, os.strerror(error_number), final_path)
    raise OSError(error_number, os.strerror(error_number), final_path)


def sync_source(pin: SourcePin, cache_root: Path, offline: bool = False) -> Path:
    """Fetch one exact Git commit into a sparse projection, then publish it atomically."""
    _validate_pin(pin)
    root = Path(os.path.abspath(os.fspath(cache_root)))
    final_path = source_path(root, pin)
    projection = _projection_fingerprint(pin)
    if offline:
        if not os.path.lexists(final_path):
            raise SourceError(
                "Pinned source is missing from the cache and offline mode forbids fetching it."
            )
        return verify_source(pin, root)
    try:
        _ensure_directory(root)
        _ensure_directory(final_path.parent)
        if os.path.lexists(final_path):
            return _verify_entry(final_path, pin)
        lock_path = _create_lock(root, pin, projection)
    except SourceError:
        raise
    except OSError:
        raise SourceError(
            "Source cache path cannot be prepared safely; inspect it and retry."
        ) from None

    staging: Path | None = None
    try:
        if os.path.lexists(final_path):
            return _verify_entry(final_path, pin)
        try:
            staging = Path(
                tempfile.mkdtemp(prefix=f".{pin.commit}.staging-", dir=final_path.parent)
            )
        except OSError:
            raise SourceError(
                "A private source staging directory could not be created safely."
            ) from None
        _fetch_source(staging, pin)
        _prepare_projection(staging, pin)
        _verify_entry(staging, pin)
        entries = _tree_entries(staging, pin)
        selected = _selected_entries(entries, pin)
        _make_read_only(staging, selected)
        _verify_entry(staging, pin)
        try:
            _publish_no_replace(staging, final_path)
        except FileExistsError:
            raise SourceError(
                "A source cache entry appeared during sync; it was left untouched."
            ) from None
        staging = None
        return _verify_entry(final_path, pin)
    except SourceError as error:
        if staging is not None and staging.exists():
            raise SourceError(
                f"{error} Failed staging was preserved at {staging}; inspect it before retrying."
            ) from None
        raise
    except (OSError, UnicodeDecodeError, subprocess.SubprocessError):
        detail = (
            f" Failed staging was preserved at {staging}; inspect it before retrying."
            if staging
            else ""
        )
        raise SourceError(f"Pinned source sync failed safely.{detail}") from None
    finally:
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            # A stale lock is safer than deleting a path that may have been replaced.
            pass
