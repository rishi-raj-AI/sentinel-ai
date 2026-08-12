from __future__ import annotations

from app.audit.logger import AuditLogger
from app.models import CommandPlan, ExecutionResult
from app.security.risk import classify_tool_call, requires_confirmation
from app.tools.registry import get_tool


class ConfirmationRequired(RuntimeError):
    pass


class Executor:
    def __init__(self, audit: AuditLogger | None = None) -> None:
        self.audit = audit or AuditLogger()

    def execute(self, plan: CommandPlan, *, confirmed: bool = False) -> list[ExecutionResult]:
        results: list[ExecutionResult] = []

        for step in plan.steps:
            risk = classify_tool_call(step)
            if requires_confirmation(risk) and not confirmed:
                raise ConfirmationRequired(
                    f"{step.tool} requires confirmation at risk level {risk.name}"
                )

            try:
                tool = get_tool(step.tool)
                output = tool(**step.arguments)
                result = ExecutionResult(tool=step.tool, success=True, output=output)
                self.audit.record(
                    tool=step.tool,
                    arguments=step.arguments,
                    risk_level=int(risk),
                    success=True,
                    output=output,
                )
            except Exception as exc:
                result = ExecutionResult(tool=step.tool, success=False, error=str(exc))
                self.audit.record(
                    tool=step.tool,
                    arguments=step.arguments,
                    risk_level=int(risk),
                    success=False,
                    error=str(exc),
                )

            results.append(result)

        return results
