"""Public M0 command surface. Validation never executes manifest data."""

from pathlib import Path
from typing import Literal

import typer
from rich.console import Console
from rich.table import Table

from snowsky_disc_lab.contracts import load_manifest
from snowsky_disc_lab.doctor import collect_diagnostics

app = typer.Typer(
    help="Firmware-free SNOWSKY DISC Lab diagnostics and schema validation.", add_completion=False
)
ui_app = typer.Typer(help="Validate UI manifest data; no builds or execution.")
firmware_app = typer.Typer(help="Validate firmware profile data; no firmware access.")
app.add_typer(ui_app, name="ui")
app.add_typer(firmware_app, name="firmware")
console = Console()
errors = Console(stderr=True)


@app.command()
def doctor() -> None:
    """Report host and tool availability without changing host settings."""
    table = Table("Check", "Status", "Detail")
    for row in collect_diagnostics():
        table.add_row(row.name, row.status, row.detail)
    console.print(table)
    console.print("Read-only checks complete. Docker daemon and runtime compatibility: NOT RUN.")


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
