from __future__ import annotations

import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
    pack: str = "core"
    optional: bool = False
    identity_pattern: str | None = None
    python_distribution: str | None = None
    homepage: str | None = None
    notes: str | None = None


class ToolRegistry:
    VERSION = "tools-v3"

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self._install_defaults()

    def _install_defaults(self) -> None:
        defaults = [
            ToolSpec("nmap", "nmap", "Nmap", "network", ["--version"], [
                ToolProfile("host-discovery", "Host Discovery", "Discover responsive hosts in an approved scope.", requires_scope=True, timeout_seconds=120),
                ToolProfile("service-inventory", "Service Inventory", "Inventory exposed TCP services on an approved target.", requires_scope=True, timeout_seconds=180),
            ], pack="network", identity_pattern=r"Nmap version"),
            ToolSpec("httpx", "httpx", "ProjectDiscovery HTTPX", "web", ["-version"], [
                ToolProfile("http-inventory", "HTTP Inventory", "Collect basic HTTP service metadata for an approved target.", requires_scope=True, timeout_seconds=90),
            ], pack="web", identity_pattern=r"(?i)(projectdiscovery|current version|httpx.*v?\d)"),
            ToolSpec("whatweb", "whatweb", "WhatWeb", "web", ["--version"], [
                ToolProfile("technology-fingerprint", "Technology Fingerprint", "Identify web technologies on an approved target.", requires_scope=True, timeout_seconds=90),
            ], pack="web", optional=True, identity_pattern=r"(?i)whatweb", notes="Optional upstream-installed adapter; not required for core web inventory."),
            ToolSpec("semgrep", "semgrep", "Semgrep", "appsec", ["--version"], [
                ToolProfile("source-audit", "Source Audit", "Run static source-code analysis against a local project.", timeout_seconds=180),
            ], pack="appsec", identity_pattern=r"\d+\.\d+"),
            ToolSpec("trivy", "trivy", "Trivy", "appsec", ["--version"], [
                ToolProfile("filesystem-audit", "Filesystem Audit", "Inspect a local project for dependency and configuration findings.", timeout_seconds=180),
            ], pack="appsec", identity_pattern=r"(?i)version"),
            ToolSpec("yara", "yara", "YARA", "malware", ["--version"], [
                ToolProfile("artifact-match", "Artifact Match", "Evaluate local artifacts against analyst-selected YARA rules.", timeout_seconds=120),
            ], pack="dfir", identity_pattern=r"\d+\.\d+"),
            ToolSpec("tshark", "tshark", "TShark", "network-forensics", ["--version"], [
                ToolProfile("pcap-summary", "PCAP Summary", "Summarize an already-acquired packet capture.", timeout_seconds=120),
            ], pack="dfir", identity_pattern=r"(?i)tshark.*wireshark"),
            ToolSpec("volatility3", "vol", "Volatility 3", "dfir", ["--help"], [
                ToolProfile("memory-info", "Memory Image Information", "Inspect metadata from an already-acquired memory image.", timeout_seconds=180),
            ], pack="dfir", python_distribution="volatility3"),

            ToolSpec("rustscan", "rustscan", "RustScan", "network", ["--version"], pack="network", optional=True, identity_pattern=r"(?i)rustscan", notes="Discovery-only until locally validated."),
            ToolSpec("masscan", "masscan", "Masscan", "network", ["--version"], pack="network", optional=True, identity_pattern=r"(?i)masscan", notes="Discovery-only until locally validated."),
            ToolSpec("nuclei", "nuclei", "Nuclei", "web", ["-version"], pack="web", optional=True, identity_pattern=r"(?i)nuclei", notes="Discovery-only until local template/runtime validation."),
            ToolSpec("ffuf", "ffuf", "ffuf", "web", ["-V"], [
                ToolProfile("content-discovery", "Rate-limited Content Discovery", "Discover paths on an approved web target using an analyst-supplied local wordlist.", requires_scope=True, requires_approval=True, timeout_seconds=120),
            ], pack="web", optional=True, identity_pattern=r"(?i)ffuf"),
            ToolSpec("gobuster", "gobuster", "Gobuster", "web", ["version"], [
                ToolProfile("directory-discovery", "Rate-limited Directory Discovery", "Enumerate paths on an approved web target using an analyst-supplied local wordlist.", requires_scope=True, requires_approval=True, timeout_seconds=120),
            ], pack="web", optional=True, identity_pattern=r"(?i)gobuster"),
            ToolSpec("katana", "katana", "Katana", "web", ["-version"], [
                ToolProfile("crawl-inventory", "Scoped Crawl Inventory", "Crawl an approved web target with conservative rate and depth limits.", requires_scope=True, timeout_seconds=120),
            ], pack="web", optional=True, identity_pattern=r"(?i)katana"),
            ToolSpec("nikto", "nikto", "Nikto", "web", ["-Version"], [
                ToolProfile("web-baseline", "Approved Web Baseline", "Run a conservative baseline web-server assessment on an approved target.", requires_scope=True, requires_approval=True, timeout_seconds=180),
            ], pack="web", optional=True, identity_pattern=r"(?i)nikto"),
            ToolSpec("checkov", "checkov", "Checkov", "appsec", ["--version"], [
                ToolProfile("iac-audit", "IaC Audit", "Analyze infrastructure-as-code in a confined local project.", timeout_seconds=180),
            ], pack="appsec", optional=True, identity_pattern=r"\d+\.\d+"),
            ToolSpec("syft", "syft", "Syft", "appsec", ["version"], [
                ToolProfile("sbom", "SBOM Generation", "Generate a software bill of materials for a confined local project.", timeout_seconds=180),
            ], pack="appsec", optional=True, identity_pattern=r"(?i)syft"),
            ToolSpec("grype", "grype", "Grype", "appsec", ["version"], [
                ToolProfile("dependency-audit", "Dependency Audit", "Analyze a confined local project for known vulnerable packages.", timeout_seconds=180),
            ], pack="appsec", optional=True, identity_pattern=r"(?i)grype"),
            ToolSpec("zeek", "zeek", "Zeek", "network-forensics", ["--version"], [
                ToolProfile("pcap-logs", "PCAP Log Extraction", "Process an already-acquired packet capture into Zeek logs.", timeout_seconds=180),
            ], pack="dfir", optional=True, identity_pattern=r"(?i)zeek"),
            ToolSpec("suricata", "suricata", "Suricata", "network-forensics", ["--build-info"], [
                ToolProfile("pcap-ids", "Offline PCAP IDS", "Evaluate an already-acquired packet capture with local Suricata rules.", timeout_seconds=240),
            ], pack="dfir", optional=True, identity_pattern=r"(?i)suricata"),
            ToolSpec("capa", "capa", "capa", "reverse-engineering", ["--version"], [
                ToolProfile("capability-analysis", "Capability Analysis", "Extract behavioral capabilities from a confined local executable artifact.", timeout_seconds=180),
            ], pack="reverse", optional=True, identity_pattern=r"(?i)capa|\d+\.\d+"),
            ToolSpec("radare2", "radare2", "radare2", "reverse-engineering", ["-v"], [
                ToolProfile("binary-info", "Binary Information", "Extract basic structure, sections, imports and symbols from a confined local binary.", timeout_seconds=120),
            ], pack="reverse", optional=True, identity_pattern=r"(?i)radare2"),
        ]
        self._tools = {tool.tool_id: tool for tool in defaults}

    def list(self, *, pack: str | None = None) -> list[dict[str, Any]]:
        specs = [self._tools[k] for k in sorted(self._tools)]
        if pack:
            specs = [spec for spec in specs if spec.pack == pack]
        return [asdict(spec) for spec in specs]

    def packs(self) -> dict[str, list[str]]:
        rows: dict[str, list[str]] = {}
        for spec in self._tools.values():
            rows.setdefault(spec.pack, []).append(spec.tool_id)
        return {pack: sorted(ids) for pack, ids in sorted(rows.items())}

    def get(self, tool_id: str) -> ToolSpec:
        if tool_id not in self._tools:
            raise KeyError(tool_id)
        return self._tools[tool_id]

    @staticmethod
    def _distribution_version(name: str | None) -> str | None:
        if not name:
            return None
        try:
            return importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            return None

    def health(self, tool_id: str | None = None) -> list[dict[str, Any]]:
        specs = [self.get(tool_id)] if tool_id else [self._tools[k] for k in sorted(self._tools)]
        rows = []
        for spec in specs:
            path = shutil.which(spec.binary)
            version = self._distribution_version(spec.python_distribution)
            error = None
            compatible = False
            if path and version is None:
                try:
                    proc = subprocess.run([path, *spec.version_args], capture_output=True, text=True, timeout=8, check=False)
                    text = "\n".join(x for x in [proc.stdout, proc.stderr] if x).strip()
                    lines = text.splitlines()
                    version = lines[0][:200] if lines else None
                    if spec.identity_pattern:
                        compatible = bool(re.search(spec.identity_pattern, text or "", re.IGNORECASE))
                    else:
                        compatible = proc.returncode == 0
                except (OSError, subprocess.SubprocessError) as exc:
                    error = str(exc)
            elif path and version is not None:
                compatible = True

            installed = bool(path)
            if installed and not compatible and not error:
                error = "binary found, but identity/version output does not match the expected security tool"
            rows.append({
                "tool_id": spec.tool_id,
                "name": spec.name,
                "binary": spec.binary,
                "pack": spec.pack,
                "optional": spec.optional,
                "installed": installed,
                "compatible": compatible,
                "ready": installed and compatible,
                "path": path,
                "version": version,
                "profiles": [p.profile_id for p in spec.profiles],
                "error": error,
            })
        return rows

    def summary(self) -> dict[str, Any]:
        rows = self.health()
        required = [r for r in rows if not r["optional"]]
        return {
            "version": self.VERSION,
            "ready_count": sum(1 for r in rows if r["ready"]),
            "total_count": len(rows),
            "required_ready": sum(1 for r in required if r["ready"]),
            "required_total": len(required),
            "packs": self.packs(),
            "tools": rows,
        }


class ToolRunner:
    """Governed adapter runner. Executes predefined argv profiles only; never invokes a shell."""

    VERSION = "runner-v2"

    def __init__(self, data_root: str | Path = "data", registry: ToolRegistry | None = None) -> None:
        self.data_root = Path(data_root)
        self.data_root.mkdir(parents=True, exist_ok=True)
        self.registry = registry or ToolRegistry()
        self.engagements = EngagementStore(self.data_root / "engagements.db")
        self.audit_path = self.data_root / "tool_audit.jsonl"
        self.project_root = (self.data_root / "projects").resolve()
        self.artifact_root = (self.data_root / "artifacts").resolve()
        self.wordlist_root = (self.data_root / "wordlists").resolve()
        self.project_root.mkdir(parents=True, exist_ok=True)
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self.wordlist_root.mkdir(parents=True, exist_ok=True)

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
        health = self.registry.health(tool_id)[0]
        if not health["ready"]:
            raise FileNotFoundError(f"tool not ready: {tool_id}: {health.get('error') or 'not installed'}")
        binary = str(health["path"])

        if tool_id == "nmap" and profile_id == "host-discovery":
            return [binary, "-sn", "--reason", self._safe_target(target or "")]
        if tool_id == "nmap" and profile_id == "service-inventory":
            return [binary, "-sT", "-sV", "--version-light", "--reason", "-T3", self._safe_target(target or "")]
        if tool_id == "httpx" and profile_id == "http-inventory":
            return [binary, "-u", self._safe_target(target or ""), "-status-code", "-title", "-tech-detect", "-json", "-silent"]
        if tool_id == "whatweb" and profile_id == "technology-fingerprint":
            return [binary, "--log-json=-", "--no-errors", self._safe_target(target or "")]
        if tool_id == "ffuf" and profile_id == "content-discovery":
            wordlist = self._confined(self.wordlist_root, path or "")
            if not wordlist.is_file():
                raise FileNotFoundError("wordlist not found")
            base = self._safe_target(target or "").rstrip("/")
            return [binary, "-w", str(wordlist), "-u", f"{base}/FUZZ", "-rate", "20", "-t", "10", "-maxtime", "60", "-of", "json", "-s"]
        if tool_id == "gobuster" and profile_id == "directory-discovery":
            wordlist = self._confined(self.wordlist_root, path or "")
            if not wordlist.is_file():
                raise FileNotFoundError("wordlist not found")
            return [binary, "dir", "-u", self._safe_target(target or ""), "-w", str(wordlist), "-t", "10", "--timeout", "5s", "--no-error", "--no-progress"]
        if tool_id == "katana" and profile_id == "crawl-inventory":
            return [binary, "-u", self._safe_target(target or ""), "-d", "2", "-rl", "20", "-silent", "-jsonl"]
        if tool_id == "nikto" and profile_id == "web-baseline":
            return [binary, "-h", self._safe_target(target or ""), "-maxtime", "120s", "-Display", "V", "-Format", "json"]
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
        if tool_id == "checkov" and profile_id == "iac-audit":
            project = self._confined(self.project_root, path or "")
            if not project.exists():
                raise FileNotFoundError("project not found")
            return [binary, "-d", str(project), "-o", "json", "--quiet"]
        if tool_id == "syft" and profile_id == "sbom":
            project = self._confined(self.project_root, path or "")
            if not project.exists():
                raise FileNotFoundError("project not found")
            return [binary, str(project), "-o", "json"]
        if tool_id == "grype" and profile_id == "dependency-audit":
            project = self._confined(self.project_root, path or "")
            if not project.exists():
                raise FileNotFoundError("project not found")
            return [binary, f"dir:{project}", "-o", "json"]
        if tool_id == "tshark" and profile_id == "pcap-summary":
            artifact = self._confined(self.artifact_root, path or "")
            if not artifact.is_file():
                raise FileNotFoundError("artifact not found")
            return [binary, "-r", str(artifact), "-q", "-z", "conv,ip"]
        if tool_id == "zeek" and profile_id == "pcap-logs":
            artifact = self._confined(self.artifact_root, path or "")
            if not artifact.is_file():
                raise FileNotFoundError("artifact not found")
            return [binary, "-r", str(artifact), "LogAscii::use_json=T"]
        if tool_id == "suricata" and profile_id == "pcap-ids":
            artifact = self._confined(self.artifact_root, path or "")
            if not artifact.is_file():
                raise FileNotFoundError("artifact not found")
            return [binary, "-r", str(artifact), "-l", str(self.artifact_root)]
        if tool_id == "volatility3" and profile_id == "memory-info":
            artifact = self._confined(self.artifact_root, path or "")
            if not artifact.is_file():
                raise FileNotFoundError("artifact not found")
            return [binary, "-f", str(artifact), "windows.info"]
        if tool_id == "capa" and profile_id == "capability-analysis":
            artifact = self._confined(self.artifact_root, path or "")
            if not artifact.is_file():
                raise FileNotFoundError("artifact not found")
            return [binary, "-j", str(artifact)]
        if tool_id == "radare2" and profile_id == "binary-info":
            artifact = self._confined(self.artifact_root, path or "")
            if not artifact.is_file():
                raise FileNotFoundError("artifact not found")
            return [binary, "-2", "-q", "-c", "ij; iSj; iij; isj", str(artifact)]
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