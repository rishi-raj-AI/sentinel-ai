from __future__ import annotations

import json

import typer
from rich import print

from app.brain.planner import plan_command
from app.executor import ConfirmationRequired, Executor

app = typer.Typer(help="Sentinel AI local assistant")


@app.callback()
def main() -> None:
    """Sentinel AI command-line interface."""


@app.command()
def run(
    command: str = typer.Argument(..., help="Natural-language command"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Pre-authorize confirmation-required actions"),
) -> None:
    plan = plan_command(command)
    if not plan.requires_action:
        print("[yellow]No registered action matched that command yet.[/yellow]")
        raise typer.Exit(code=2)

    executor = Executor()
    try:
        results = executor.execute(plan, confirmed=yes)
    except ConfirmationRequired as exc:
        print(f"[bold yellow]Authorization required:[/bold yellow] {exc}")
        if not typer.confirm("Proceed with this action?"):
            print("[yellow]Action cancelled by owner.[/yellow]")
            raise typer.Exit(code=1)
        results = executor.execute(plan, confirmed=True)

    print(json.dumps([item.model_dump() for item in results], indent=2, default=str))


if __name__ == "__main__":
    app()
