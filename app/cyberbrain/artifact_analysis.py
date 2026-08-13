from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any


class ArtifactAnalysisEngine:
    VERSION = "X5.0"
    URL_RE = re.compile(rb"https?://[^\s\x00\"'<>]{4,}")
    IPV4_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        return round(-sum((n / total) * math.log2(n / total) for n in counts.values()), 4)

    @staticmethod
    def _kind(data: bytes, suffix: str) -> str:
        if data.startswith(b"MZ"):
            return "pe"
        if data.startswith(b"\x7fELF"):
            return "elf"
        if data[:4] in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"}:
            return "mach-o"
        if data.startswith(b"PK\x03\x04"):
            return "zip-container"
        if data.startswith(b"%PDF"):
            return "pdf"
        if suffix in {".ps1", ".py", ".js", ".vbs", ".sh", ".bat", ".cmd"}:
            return "script"
        return "unknown"

    @staticmethod
    def _strings(data: bytes, *, minimum: int = 5, limit: int = 500) -> list[str]:
        pattern = re.compile(rb"[\x20-\x7e]{%d,}" % minimum)
        rows = []
        for match in pattern.finditer(data):
            rows.append(match.group(0).decode("utf-8", errors="replace"))
            if len(rows) >= limit:
                break
        return rows

    @staticmethod
    def _unique(decoded: list[bytes], limit: int = 100) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for item in decoded:
            text = item.decode("utf-8", errors="replace")
            if text not in seen:
                seen.add(text)
                out.append(text)
            if len(out) >= limit:
                break
        return out

    def analyze(self, path: str | Path, *, max_bytes: int = 32 * 1024 * 1024) -> dict[str, Any]:
        target = Path(path).expanduser().resolve()
        if not target.is_file():
            raise FileNotFoundError(str(target))
        size = target.stat().st_size
        if size > max_bytes:
            raise ValueError(f"artifact exceeds analysis limit: {size} > {max_bytes}")
        data = target.read_bytes()
        strings = self._strings(data)
        lower = "\n".join(strings).lower()
        indicators = []
        for label, terms in {
            "process-execution": ("createprocess", "system(", "subprocess", "cmd.exe", "powershell"),
            "network-capability": ("winsock", "socket", "http://", "https://", "curl", "wget"),
            "persistence-reference": ("runonce", "startup", "launchagents", "systemd", "schtasks"),
            "credential-reference": ("password", "credential", "keychain", "lsass", "token"),
        }.items():
            hits = [term for term in terms if term in lower]
            if hits:
                indicators.append({"category": label, "matched_terms": hits})
        return {
            "version": self.VERSION,
            "path": str(target),
            "filename": target.name,
            "size_bytes": size,
            "kind": self._kind(data, target.suffix.lower()),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
            "entropy": self._entropy(data),
            "high_entropy": self._entropy(data) >= 7.2,
            "strings": strings[:200],
            "urls": self._unique(self.URL_RE.findall(data)),
            "ipv4": self._unique(self.IPV4_RE.findall(data)),
            "emails": self._unique(self.EMAIL_RE.findall(data)),
            "behavioral_indicators": indicators,
            "assessment": "Static artifact observations only; behavioral indicators are not a maliciousness verdict.",
        }
