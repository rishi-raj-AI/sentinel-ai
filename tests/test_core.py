from pathlib import Path

from app.brain.planner import plan_command
from app.executor import Executor


def test_planner_creates_registered_list_action() -> None:
    plan = plan_command("list .")
    assert plan.requires_action is True
    assert plan.steps[0].tool == "filesystem.list_directory"


def test_unknown_command_does_not_execute() -> None:
    plan = plan_command("launch hyperspace")
    assert plan.requires_action is False
    assert plan.steps == []


def test_sha256_execution(tmp_path: Path) -> None:
    evidence = tmp_path / "sample.txt"
    evidence.write_text("sentinel", encoding="utf-8")
    plan = plan_command(f"sha256 {evidence}")
    executor = Executor(db_path_for_test(tmp_path))
    result = executor.execute(plan)
    assert result[0].success is True
    assert len(result[0].output) == 64


def db_path_for_test(tmp_path: Path):
    from app.audit.logger import AuditLogger

    return AuditLogger(str(tmp_path / "audit.db"))
