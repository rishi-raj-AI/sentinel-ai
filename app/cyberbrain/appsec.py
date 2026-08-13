from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class AppSecFinding:
    category: str
    severity: str
    file: str
    line: int | None
    summary: str
    evidence: str


class AppSecAnalyzer:
    """Read-only static AppSec and software-supply-chain analysis."""

    VERSION = "X7.0"
    MAX_FILE_BYTES = 2 * 1024 * 1024
    TEXT_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php", ".yaml", ".yml", ".json", ".toml", ".ini", ".env", ".tf", ".sh"}
    MANIFESTS = {"requirements.txt", "package.json", "pyproject.toml", "pom.xml", "go.mod", "Gemfile", "composer.json"}
    SECRET_PATTERNS = [
        ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
        ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("generic-secret", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]([^'\"\s]{8,})")),
    ]
    RISK_PATTERNS = [
        ("insecure-tls", "medium", re.compile(r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false)")),
        ("wildcard-cors", "medium", re.compile(r"(?i)(allow_origins\s*=\s*\[?['\"]\*|Access-Control-Allow-Origin\s*[:=]\s*['\"]\*)")),
        ("dangerous-eval", "high", re.compile(r"\b(eval|exec)\s*\(")),
        ("shell-execution", "medium", re.compile(r"(?i)(shell\s*=\s*True|child_process\.exec\s*\()")),
        ("public-cloud-rule", "high", re.compile(r"0\.0\.0\.0/0|::/0")),
    ]

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _manifest_components(self, path: Path, text: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        if path.name == "requirements.txt":
            for raw in text.splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                name = re.split(r"[<>=!~ ]", line, maxsplit=1)[0].strip()
                rows.append({"ecosystem": "python", "name": name, "declaration": line})
        elif path.name == "package.json":
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return rows
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                for name, version in (data.get(section) or {}).items():
                    rows.append({"ecosystem": "npm", "name": name, "declaration": str(version), "scope": section})
        elif path.name == "go.mod":
            for raw in text.splitlines():
                parts = raw.strip().split()
                if len(parts) >= 2 and not parts[0].startswith(("module", "go", "require", "(" , ")")):
                    rows.append({"ecosystem": "go", "name": parts[0], "declaration": parts[1]})
        return rows

    def analyze(self, root: str | Path, *, max_files: int = 5000) -> dict[str, Any]:
        base = Path(root).resolve()
        if not base.is_dir():
            raise FileNotFoundError(base)
        findings: list[AppSecFinding] = []
        components: list[dict[str, Any]] = []
        files_scanned = 0
        manifests = 0
        skipped_large = 0
        for path in sorted(base.rglob("*")):
            if files_scanned >= max_files:
                break
            if not path.is_file() or any(part.startswith(".git") for part in path.parts):
                continue
            if path.suffix.lower() not in self.TEXT_SUFFIXES and path.name not in self.MANIFESTS:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > self.MAX_FILE_BYTES:
                skipped_large += 1
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            files_scanned += 1
            rel = str(path.relative_to(base))
            if path.name in self.MANIFESTS:
                manifests += 1
                for row in self._manifest_components(path, text):
                    row["file"] = rel
                    components.append(row)
            for idx, line in enumerate(text.splitlines(), start=1):
                for category, pattern in self.SECRET_PATTERNS:
                    if pattern.search(line):
                        findings.append(AppSecFinding(category, "high", rel, idx, "Potential secret-like material detected", line[:240]))
                for category, severity, pattern in self.RISK_PATTERNS:
                    if pattern.search(line):
                        findings.append(AppSecFinding(category, severity, rel, idx, "Potentially risky static configuration or code pattern", line[:240]))
        severity_counts: dict[str, int] = {}
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        return {
            "version": self.VERSION,
            "root": str(base),
            "files_scanned": files_scanned,
            "manifests": manifests,
            "components": components,
            "component_count": len(components),
            "findings": [asdict(f) for f in findings],
            "finding_count": len(findings),
            "severity_counts": severity_counts,
            "skipped_large_files": skipped_large,
            "policy": {"read_only": True, "static_analysis_only": True, "pattern_findings_require_review": True},
        }
