from pathlib import Path

import pytest

from app.audit.logger import AuditLogger
from app.brain.planner import plan_command
from app.executor import ConfirmationRequired, Executor
from app.memory.store import MemoryStore


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
    executor = Executor(AuditLogger(str(tmp_path / "audit.db")))
    result = executor.execute(plan)
    assert result[0].success is True
    assert len(result[0].output) == 64


def test_modification_requires_confirmation(tmp_path: Path) -> None:
    plan = plan_command(f"mkdir {tmp_path / 'created'}")
    executor = Executor(AuditLogger(str(tmp_path / "audit.db")))
    with pytest.raises(ConfirmationRequired):
        executor.execute(plan)
    result = executor.execute(plan, confirmed=True)
    assert result[0].success is True
    assert (tmp_path / "created").is_dir()


def test_memory_persists_between_instances(tmp_path: Path) -> None:
    db = str(tmp_path / "memory.db")
    first = MemoryStore(db)
    first.set("owner_name", "Rishi")
    second = MemoryStore(db)
    assert second.get("owner_name") == "Rishi"
