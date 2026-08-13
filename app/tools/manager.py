from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.tools.integration import ToolRegistry


@dataclass(slots=True)
class InstallRecipe:
    tool_id: str
    manager: str
    argv: list[str]
    description: str


class ToolManager:
    """Case capability planner plus governed installer for defensive/offline tools.

    The manager never accepts arbitrary command text. Installation is restricted to
    recipes defined in code and requires explicit operator confirmation.
    """

    VERSION = "tool-manager-v1"

    def __init__(self, data_root: str | Path = "data", registry: ToolRegistry | None = None) -> None:
        self.data_root = Path(data_root)
        self.data_root.mkdir(parents=True, exist_ok=True)
        self.registry = registry or ToolRegistry()
        self.audit_path = self.data_root / "tool_manager_audit.jsonl"
        py = sys.executable
        self.recipes: dict[str, InstallRecipe] = {
            "semgrep": InstallRecipe("semgrep", "pip", [py, "-m", "pip", "install", "--upgrade", "semgrep"], "Static source-code analysis"),
            "volatility3": InstallRecipe("volatility3", "pip", [py, "-m", "pip", "install", "--upgrade", "volatility3"], "Memory-forensics analysis"),
            "capa": InstallRecipe("capa", "pip", [py, "-m", "pip", "install", "--upgrade", "flare-capa"], "Executable capability analysis"),
            "trivy": InstallRecipe("trivy", "homebrew", ["brew", "install", "trivy"], "Filesystem/dependency analysis"),
            "checkov": InstallRecipe("checkov", "homebrew", ["brew", "install", "checkov"], "Infrastructure-as-code analysis"),
            "yara": InstallRecipe("yara", "homebrew", ["brew", "install", "yara"], "Rule-based artifact matching"),
            "zeek": InstallRecipe("zeek", "homebrew", ["brew", "install", "zeek"], "Offline network-forensics analysis"),
            "radare2": InstallRecipe("radare2", "homebrew", ["brew", "install", "radare2"], "Binary structure inspection"),
        }

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _audit(self, row: dict[str, Any]) -> None:
        with self.audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    @staticmethod
    def _requirements(objective: str) -> list[tuple[str, str]]:
        text = objective.casefold()
        rows: list[tuple[str, str]] = []
        def add(tool: str, reason: str) -> None:
            if tool not in {x[0] for x in rows}:
                rows.append((tool, reason))
        if any(x in text for x in ("network", "host", "service", "asset")):
            add("nmap", "network/service inventory")
        if any(x in text for x in ("web", "http", "api", "website")):
            add("httpx", "HTTP service inventory")
            add("katana", "web surface inventory")
        if any(x in text for x in ("source", "code", "appsec", "repository")):
            add("semgrep", "source-code analysis")
            add("trivy", "dependency/configuration analysis")
        if any(x in text for x in ("terraform", "iac", "cloudformation")):
            add("checkov", "infrastructure-as-code analysis")
        if any(x in text for x in ("pcap", "packet", "traffic", "network forensic")):
            add("tshark", "packet-capture summarization")
            add("zeek", "network-forensics log extraction")
        if any(x in text for x in ("memory", "ram", "memory image")):
            add("volatility3", "memory-forensics analysis")
        if any(x in text for x in ("malware", "binary", "reverse", "executable", "sample")):
            add("yara", "artifact matching")
            add("capa", "capability analysis")
            add("radare2", "binary structure inspection")
        if not rows:
            add("trivy", "baseline local security analysis")
        return rows

    def inventory(self) -> dict[str, Any]:
        summary = self.registry.summary()
        for row in summary["tools"]:
            recipe = self.recipes.get(row["tool_id"])
            row["one_click_install"] = bool(recipe and platform.system() in ("Darwin", "Linux"))
            row["install_manager"] = recipe.manager if recipe else None
            row["install_description"] = recipe.description if recipe else None
        summary["manager_version"] = self.VERSION
        return summary

    def plan(self, objective: str) -> dict[str, Any]:
        if not objective.strip():
            raise ValueError("objective is required")
        health = {row["tool_id"]: row for row in self.registry.health()}
        requirements = []
        missing = []
        for tool_id, reason in self._requirements(objective):
            row = health.get(tool_id, {"installed": False, "compatible": False, "ready": False, "profiles": []})
            recipe = self.recipes.get(tool_id)
            item = {
                "tool_id": tool_id,
                "reason": reason,
                "ready": bool(row.get("ready")),
                "installed": bool(row.get("installed")),
                "compatible": bool(row.get("compatible")),
                "version": row.get("version"),
                "profiles": row.get("profiles", []),
                "one_click_install": bool(recipe),
                "install_manager": recipe.manager if recipe else None,
                "status": "ready" if row.get("ready") else ("repair" if row.get("installed") else "missing"),
            }
            requirements.append(item)
            if not item["ready"]:
                missing.append(item)
        return {
            "version": self.VERSION,
            "objective": objective,
            "required_tools": requirements,
            "missing_or_incompatible": missing,
            "ready_to_execute": not missing,
            "next_action": "execute-approved-workflow" if not missing else "prepare-toolchain",
            "policy": {
                "installation_requires_operator_confirmation": True,
                "arbitrary_shell_commands": False,
                "target_actions_require_registered_scope": True,
            },
        }

    def install(self, tool_id: str, *, actor: str, confirmed: bool = False) -> dict[str, Any]:
        if not confirmed:
            raise PermissionError("operator confirmation is required")
        recipe = self.recipes.get(tool_id)
        if not recipe:
            raise KeyError("tool does not have a one-click governed install recipe")
        installer = shutil.which(recipe.argv[0])
        if not installer:
            raise FileNotFoundError(f"required installer is unavailable: {recipe.argv[0]}")
        argv = [installer, *recipe.argv[1:]]
        audit = {"timestamp": self._now(), "actor": actor, "action": "tool.install", "tool_id": tool_id, "manager": recipe.manager, "status": "started"}
        self._audit(audit)
        started = time.perf_counter()
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=900, check=False)
        except subprocess.TimeoutExpired as exc:
            self._audit({**audit, "status": "timeout"})
            raise TimeoutError("tool installation timed out") from exc
        health = self.registry.health(tool_id)[0]
        result = {
            "version": self.VERSION,
            "tool_id": tool_id,
            "returncode": proc.returncode,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "ready": bool(health.get("ready")),
            "health": health,
            "stdout_tail": (proc.stdout or "")[-20000:],
            "stderr_tail": (proc.stderr or "")[-20000:],
        }
        self._audit({**audit, "status": "completed", "returncode": proc.returncode, "ready": result["ready"]})
        return result

    def audit(self, limit: int = 100) -> list[dict[str, Any]]:
        if not self.audit_path.is_file():
            return []
        rows: list[dict[str, Any]] = []
        for line in self.audit_path.read_text(encoding="utf-8", errors="replace").splitlines()[-max(1, min(limit, 1000)):]:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return list(reversed(rows))
