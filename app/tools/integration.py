from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from app.cyberbrain.engagements import EngagementStore


@dataclass(slots=True)
class ToolProfile:
    profile_id: str
    name: str
    purpose: str
    action_class: str = "analysis"
    requires_scope: bool = False
    requires_approval: bool = False
    timeout_seconds: int = 60


@dataclass(slots=True)
class ToolSpec:
    tool_id: str
    binary: str
    name: str
    domain: str
    version_args: list[str]
    profiles: list[ToolProfile] = field(default_factory=list)
    homepage: str | None = None
    notes: str | None = None


class ToolRegistry:
    VERSION = "tools-v1"

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self._install_defaults()

    def _install_defaults(self) -> None:
        defaults = [
            ToolSpec("nmap", "nmap", "Nmap", "network", ["--version"], [
                ToolProfile("host-discovery", "Host Discovery", "Discover responsive hosts in an approved scope.", requires_scope=True, timeout_seconds=120),
                ToolProfile("service-inventory", "Service Inventory", "Inventory exposed TCP services on an approved target.", requires_scope=True, timeout_seconds=180),
            ]),
            ToolSpec("httpx", "httpx", "HTTPX", "web", ["-version"], [
                ToolProfile("http-inventory", "HTTP Inventory", "Collect basic HTTP service metadata for an approved target.", requires_scope=True, timeout_seconds=90),
            ]),
            ToolSpec("whatweb", "whatweb", "WhatWeb", "web", ["--version"], [
                ToolProfile("technology-fingerprint", "Technology Fingerprint", "Identify web technologies on an approved target.", requires_scope=True, timeout_seconds=90),
            ]),
            ToolSpec("semgrep", "semgrep", "Semgrep", "appsec", ["--version"], [
                ToolProfile("source-audit", "Source Audit", "Run static source-code analysis against a local project.", timeout_seconds=180),
            ]),
            ToolSpec("trivy", "trivy", "Trivy", "appsec", ["--version"], [
                ToolProfile("filesystem-audit", "Filesystem Audit", "Inspect a local project for dependency and configuration findings.", timeout_seconds=180),
            ]),
            ToolSpec("yara", "yara", "YARA", "malware", ["--version"], [
                ToolProfile("artifact-match", "Artifact Match", "Evaluate local artifacts against analyst-selected YARA rules.", timeout_seconds=120),
            ]),
            ToolSpec("tshark", "tshark", "TShark", "network-forensics", ["--version"], [
                ToolProfile("pcap-summary", "PCAP Summary", "Summarize an already-acquired packet capture.", timeout_seconds=120),
            ]),
            ToolSpec("volatility3", "vol", "Volatility 3", "dfir", ["--help"], [
                ToolProfile("memory-info", "Memory Image Information", "Inspect metadata from an already-acquired memory image.", timeout_seconds=180),
            ]),
        ]
        self._tools = {tool.tool_id: tool for tool in defaults}

    def list(self) -> list[dict[str, Any]]:
        return [asdict(self._tools[k]) for k in sorted(self._tools)]

    def get(self, tool_id: str) -> ToolSpec:
        if tool_id not in self._tools:
            raise KeyError(tool_id)
        return self._tools[tool_id]

    def health(self, tool_id: str | None = None) -> list[dict[str, Any]]:
        specs = [self.get(tool_id)] if tool_id else [self._tools[k] for k in sorted(self._tools)]
        rows = []
        for spec in specs:
            path = shutil.which(spec.binary)
            version = None
            error = None
            if path:
                try:
                    proc = subprocess.run([path, *spec.version_args], capture_output=True, text=True, timeout=8, check=False)
                    text = (proc.stdout or proc.stderr or "").strip().splitlines()
                    version = text[0][:200] if text else None
                except (OSError, subprocess.SubprocessError) as exc:
                    error = str(exc)
            rows.append({"tool_id": spec.tool_id, "name": spec.name, "binary": spec.binary, "installed": bool(path), "path": path, "version": version, "error": error})
        return rows


class ToolRunner:
    """Governed adapter runner. Executes predefined argv profiles only; never invokes a shell."""

    VERSION = "runner-v1"

    def __init__(self, data_root: str | Path = "data", registry: ToolRegistry | None = None) -> None:
        self.data_root = Path(data_root)
        self.data_root.mkdir(parents=True, exist_ok=True)
        self.registry = registry or ToolRegistry()
        self.engagements = EngagementStore(self.data_root / "engagements.db")
        self.audit_path = self.data_root / "tool_audit.jsonl"
        self.project_root = (self.data_root / "projects").resolve()
        self.artifact_root = (self.data_root / "artifacts").resolve()
        self.project_root.mkdir(parents=True, exist_ok=True)
        self.artifact_root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _safe_target(value: str) -> str:
        value = value.strip()
        if not value or len(value) > 512 or re.search(r"[\x00\r\n]", value):
            raise ValueError("invalid target")
        return value

    @staticmethod
    def _profile(spec: ToolSpec, profile_id: str) -> ToolProfile:
        for profile in spec.profiles:
            if profile.profile_id == profile_id:
                return profile
        raise KeyError(profile_id)

    @staticmethod
    def _confined(root: Path, relative: str) -> Path:
        candidate = (root / relative).resolve()
        if candidate != root and root not in candidate.parents:
            raise PermissionError("path escapes configured tool workspace")
        return candidate

    def _argv(self, tool_id: str, profile_id: str, target: str | None, path: str | None) -> list[str]:
        spec = self.registry.get(tool_id)
        binary = shutil.which(spec.binary)
        if not binary:
            raise FileNotFoundError(f"tool not installed: {tool_id}")

        if tool_id == "nmap" and profile_id == "host-discovery":
            return [binary, "-sn", "--reason", self._safe_target(target or "")]
        if tool_id == "nmap" and profile_id == "service-inventory":
            return [binary, "-sT", "-sV", "--version-light", "--reason", "-T3", self._safe_target(target or "")]
        if tool_id == "httpx" and profile_id == "http-inventory":
            return [binary, "-u", self._safe_target(target or ""), "-status-code", "-title", "-tech-detect", "-json", "-silent"]
        if tool_id == "whatweb" and profile_id == "technology-fingerprint":
            return [binary, "--log-json=-", "--no-errors", self._safe_target(target or "")]
        if tool_id == "semgrep" and profile_id == "source-audit":
            project = self._confined(self.project_root, path or "")
            if not project.exists():
                raise FileNotFoundError("project not found")
            return [binary, "scan", "--config", "auto", "--json", "--metrics", "off", str(project)]
        if tool_id == "trivy" and profile_id == "filesystem-audit":
            project = self._confined(self.project_root, path or "")
            if not project.exists():
                raise FileNotFoundError("project not found")
            return [binary, "fs", "--format", "json", "--scanners", "vuln,misconfig,secret", str(project)]
        if tool_id == "tshark" and profile_id == "pcap-summary":
            artifact = self._confined(self.artifact_root, path or "")
            if not artifact.is_file():
                raise FileNotFoundError("artifact not found")
            return [binary, "-r", str(artifact), "-q", "-z", "conv,ip"]
        if tool_id == "volatility3" and profile_id == "memory-info":
            artifact = self._confined(self.artifact_root, path or "")
            if not artifact.is_file():
                raise FileNotFoundError("artifact not found")
            return [binary, "-f", str(artifact), "windows.info"]
        raise ValueError("profile requires adapter-specific configuration not yet registered")

    def _audit(self, row: dict[str, Any]) -> None:
        with self.audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    def execute(self, *, tool_id: str, profile_id: str, actor: str, engagement_id: str | None = None, target: str | None = None, path: str | None = None, approved: bool = False) -> dict[str, Any]:
        spec = self.registry.get(tool_id)
        profile = self._profile(spec, profile_id)
        if profile.requires_scope:
            if not engagement_id or not target:
                raise PermissionError("registered engagement and target are required")
            if not self.engagements.in_scope(engagement_id, target):
                raise PermissionError("target is outside registered engagement scope")
        if profile.requires_approval and not approved:
            raise PermissionError("human approval required")

        argv = self._argv(tool_id, profile_id, target, path)
        started = time.perf_counter()
        audit = {"timestamp": self._now(), "actor": actor, "tool_id": tool_id, "profile_id": profile_id, "engagement_id": engagement_id, "target": target, "path": path, "argv_redacted": [Path(argv[0]).name, *argv[1:]], "status": "started"}
        self._audit(audit)
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=max(5, min(profile.timeout_seconds, 600)), check=False, env={**os.environ, "LC_ALL": "C"})
            result = {"version": self.VERSION, "tool_id": tool_id, "profile_id": profile_id, "returncode": proc.returncode, "duration_ms": round((time.perf_counter() - started) * 1000, 2), "stdout": (proc.stdout or "")[:1_000_000], "stderr": (proc.stderr or "")[:100_000], "scope_enforced": profile.requires_scope, "human_approval_required": profile.requires_approval}
            self._audit({**audit, "status": "completed", "returncode": proc.returncode, "duration_ms": result["duration_ms"]})
            return result
        except subprocess.TimeoutExpired as exc:
            self._audit({**audit, "status": "timeout"})
            raise TimeoutError(f"tool execution timed out after {profile.timeout_seconds}s") from exc

    def audit(self, limit: int = 100) -> list[dict[str, Any]]:
        if not self.audit_path.is_file():
            return []
        rows = []
        for line in self.audit_path.read_text(encoding="utf-8", errors="replace").splitlines()[-max(1, min(limit, 1000)):]:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return list(reversed(rows))
