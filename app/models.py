from __future__ import annotations

from enum import IntEnum
from typing import Any

from pydantic import BaseModel, Field


class RiskLevel(IntEnum):
    READ = 0
    MODIFICATION = 1
    SYSTEM = 2
    DESTRUCTIVE = 3


class ToolCall(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class CommandPlan(BaseModel):
    intent: str
    requires_action: bool = True
    steps: list[ToolCall] = Field(default_factory=list)


class ExecutionResult(BaseModel):
    tool: str
    success: bool
    output: Any = None
    error: str | None = None
