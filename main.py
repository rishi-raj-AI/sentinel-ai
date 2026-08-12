from __future__ import annotations

import json

import typer
from rich import print

from app.brain.planner import plan_command
from app.executor import Executor

app = typer.Typer(help="Sentinel AI Phase 1 local assistant")


@app.command()
def run(command: str = typer.Argument(..., help="Natural-language command")) -> None:
    plan = plan_command(command)
    if not plan.requires_action:
        print("[yellow]No registered action matched that command yet.[/yellow]")
        raise typer.Exit(code=2)

    results = Executor().execute(plan)
    print(json.dumps([item.model_dump() for item in results], indent=2, default=str))


if __name__ == "__main__":
    app()
