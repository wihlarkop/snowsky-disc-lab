"""Public M0 command surface. Validation never executes manifest data."""

from pathlib import Path
from typing import Annotated, Literal

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from snowsky_disc_lab.contracts import load_manifest
from snowsky_disc_lab.doctor import collect_diagnostics
from snowsky_disc_lab.firmware_intake import inspect_firmware
from snowsky_disc_lab.source_lock import SourcePin, load_source_lock
from snowsky_disc_lab.sources import (
    DEFAULT_CACHE_DIR,
    source_cache_root,
    source_path,
    sync_source,
    verify_source,
)

app = typer.Typer(
    help="Firmware-free SNOWSKY DISC Lab diagnostics and schema validation.", add_completion=False
)
ui_app = typer.Typer(help="Validate UI manifest data; no builds or execution.")
firmware_app = typer.Typer(
    help="Validate profiles or inspect local candidate inputs; no extraction."
)
sources_app = typer.Typer(help="Resolve exact source pins into an isolated source-only cache.")
app.add_typer(ui_app, name="ui")
app.add_typer(firmware_app, name="firmware")
app.add_typer(sources_app, name="sources")
console = Console()
errors = Console(stderr=True)
DEFAULT_SOURCE_LOCK = Path("upstreams.lock.yaml")
LockOption = Annotated[Path, typer.Option(help="Versioned source lock YAML.")]


@app.command()
def doctor(
    lock: LockOption = DEFAULT_SOURCE_LOCK,
    cache_dir: str = typer.Option(DEFAULT_CACHE_DIR, help="Relative to the lock file's folder."),
    docker_daemon: bool = typer.Option(
        False, help="Opt in to contacting the configured Docker daemon/context (possibly remote)."
    ),
) -> None:
    """Report host and tool availability without changing host settings."""
    try:
        root = source_cache_root(lock, cache_dir)
    except ValueError as error:
        errors.print(str(error), markup=False)
        raise typer.Exit(code=2) from None
    table = Table()
    table.add_column("Check", overflow="fold")
    table.add_column("Status", overflow="fold")
    table.add_column("Observation / next step", overflow="fold")
    for row in collect_diagnostics(root, docker_daemon=docker_daemon):
        detail = row.detail + (f"\nAction: {row.remediation}" if row.remediation else "")
        table.add_row(*(Text(value, overflow="fold") for value in (row.name, row.status, detail)))
    console.print(table)
    console.print("Read-only checks complete. QEMU/runtime compatibility: NOT VERIFIED.")
    if not docker_daemon:
        console.print("Docker daemon contact: NOT RUN (opt in with --docker-daemon).")


def validate(path: Path, kind: Literal["ui", "firmware"]) -> None:
    try:
        load_manifest(path, kind)
    except OSError:
        errors.print(
            "Invalid manifest: file is missing, inaccessible, or not a regular readable file.",
            markup=False,
        )
        raise typer.Exit(code=2) from None
    except ValueError as error:
        # Loader messages contain field names/error categories, never manifest values.
        errors.print(str(error), markup=False, highlight=False)
        errors.print(f"See schemas/lab-{kind}-v1.schema.json.", markup=False)
        raise typer.Exit(code=2) from None
    console.print(
        "Schema valid. Claims only; binary/runtime compatibility, vendor authenticity, "
        "and firmware support: NOT VERIFIED.",
        markup=False,
    )


@ui_app.command("validate")
def ui_validate(manifest: Path) -> None:
    """Validate a lab-ui/v1 YAML manifest without reading its output binary."""
    validate(manifest, "ui")


@firmware_app.command("validate")
def firmware_validate(profile: Path) -> None:
    """Validate a lab-firmware/v1 YAML profile as data only."""
    validate(profile, "firmware")


@firmware_app.command("inspect")
def firmware_inspect(
    candidate: Path,
    output_format: Annotated[Literal["text", "json"], typer.Option("--format")] = "text",
) -> None:
    """Inspect a local ZIP or package directory offline, without extracting or decrypting."""
    receipt = inspect_firmware(candidate)
    if output_format == "json":
        typer.echo(receipt.model_dump_json(indent=2))
    else:
        console.print(f"Candidate structure: {receipt.status.upper()}", markup=False)
        console.print(
            f"Input format: {receipt.input_format}; rootfs chunks: {receipt.chunk_count}/77"
        )
        for condition in receipt.conditions:
            console.print(f"{condition.check}: {condition.status} ({condition.code})", markup=False)
        console.print(
            "Structural acceptance only. Vendor authenticity/product/plaintext identity and "
            "compatibility: UNVERIFIED. Extraction/execution: NOT AUTHORIZED.",
            markup=False,
        )
    if receipt.status == "refused":
        raise typer.Exit(code=2)


def source_inputs(lock: Path, cache_dir: str, source: str | None) -> tuple[list[SourcePin], Path]:
    root = source_cache_root(lock, cache_dir)
    pins = load_source_lock(lock).sources
    if source is not None:
        pins = [pin for pin in pins if pin.id == source]
        if not pins:
            raise ValueError("Unknown source identifier; run sources list.")
    # Keep lexical paths intact: the manager checks every cache component for links.
    return pins, root


def source_command(
    operation: Literal["list", "sync", "verify"],
    lock: Path,
    cache_dir: str,
    source: str | None,
    offline: bool = False,
) -> None:
    try:
        pins, root = source_inputs(lock, cache_dir, source)
        for pin in pins:
            if operation == "list":
                path = source_path(root, pin)
                console.print(f"{pin.id} {pin.commit} {pin.repository}", markup=False)
                console.print(f"  Source projection: {', '.join(pin.include_paths)}", markup=False)
                console.print(f"  Cache: {path} (not verified by list)", markup=False)
            else:
                path = (
                    sync_source(pin, root, offline=offline)
                    if operation == "sync"
                    else verify_source(pin, root)
                )
                console.print(f"{pin.id}: source integrity verified at {path}", markup=False)
        console.print("Source identity only; builds and runtime compatibility: NOT VERIFIED.")
    except OSError:
        errors.print("Source operation failed: file, cache, or Git is inaccessible.", markup=False)
        raise typer.Exit(code=2) from None
    except ValueError as error:
        errors.print(str(error), markup=False, highlight=False)
        raise typer.Exit(code=2) from None


@sources_app.command("list")
def sources_list(
    lock: LockOption = DEFAULT_SOURCE_LOCK,
    cache_dir: str = typer.Option(DEFAULT_CACHE_DIR, help="Relative to the lock file's folder."),
    source: str | None = typer.Option(None, help="Select one locked source identifier."),
) -> None:
    """List immutable identities without accessing the network or changing the cache."""
    source_command("list", lock, cache_dir, source)


@sources_app.command("sync")
def sources_sync(
    lock: LockOption = DEFAULT_SOURCE_LOCK,
    cache_dir: str = typer.Option(DEFAULT_CACHE_DIR, help="Relative to the lock file's folder."),
    source: str | None = typer.Option(None, help="Select one locked source identifier."),
    offline: bool = typer.Option(False, help="Require existing valid cached sources; never fetch."),
) -> None:
    """Fetch only missing pinned source projections; refuse altered cache entries."""
    source_command("sync", lock, cache_dir, source, offline)


@sources_app.command("verify")
def sources_verify(
    lock: LockOption = DEFAULT_SOURCE_LOCK,
    cache_dir: str = typer.Option(DEFAULT_CACHE_DIR, help="Relative to the lock file's folder."),
    source: str | None = typer.Option(None, help="Select one locked source identifier."),
) -> None:
    """Verify cached source identity and bytes entirely offline, without repairs."""
    source_command("verify", lock, cache_dir, source)
