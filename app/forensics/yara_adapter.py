from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from app.forensics.timeline import TimelineEvent, TimelineStore


class YaraAdapter:
    """Controlled YARA scanner for registered forensic evidence.

    The adapter never executes evidence. It invokes the local YARA CLI against one
    explicit evidence file and one explicit rule file, then records matches as
    normalized timeline events for downstream graph/investigation use.
    """

    def __init__(self, case_dir: str | Path) -> None:
        self.case_dir = Path(case_dir)
        self.timeline = TimelineStore(self.case_dir)

    @staticmethod
    def executable() -> str | None:
        return shutil.which("yara")

    @classmethod
    def status(cls) -> dict[str, Any]:
        executable = cls.executable()
        if not executable:
            return {"available": False, "executable": None, "message": "yara not found on PATH"}
        completed = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=20, check=False)
        text = (completed.stdout or completed.stderr).strip()
        return {
            "available": completed.returncode == 0,
            "executable": executable,
            "return_code": completed.returncode,
            "version": text.splitlines()[0] if text else None,
        }

    def scan(
        self,
        evidence_path: str,
        rule_path: str,
        *,
        evidence_id: str | None = None,
        timeout_seconds: int = 60,
    ) -> dict[str, Any]:
        executable = self.executable()
        if not executable:
            raise RuntimeError("yara is not installed or not on PATH")

        evidence = Path(evidence_path).expanduser().resolve()
        rules = Path(rule_path).expanduser().resolve()
        if not evidence.is_file():
            raise FileNotFoundError(f"Evidence file not found: {evidence}")
        if not rules.is_file():
            raise FileNotFoundError(f"YARA rule file not found: {rules}")

        completed = subprocess.run(
            [executable, "-m", "-s", str(rules), str(evidence)],
            capture_output=True,
            text=True,
            timeout=max(1, min(timeout_seconds, 300)),
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or f"yara exited {completed.returncode}")

        matches = self._parse_output(completed.stdout)
        events: list[TimelineEvent] = []
        for match in matches:
            rule = match["rule"]
            events.append(
                TimelineEvent(
                    timestamp=TimelineStore.normalize_timestamp(None),
                    source="yara",
                    event_type="yara_match",
                    summary=f"YARA match: {rule}",
                    details={
                        "rule": rule,
                        "namespace": match.get("namespace"),
                        "tags": match.get("tags", []),
                        "metadata": match.get("metadata", {}),
                        "strings": match.get("strings", []),
                        "evidence_path": str(evidence),
                        "rule_path": str(rules),
                    },
                    evidence_id=evidence_id,
                )
            )

        ingested = self.timeline.extend(events)
        return {
            "evidence_path": str(evidence),
            "rule_path": str(rules),
            "match_count": len(matches),
            "matches": matches,
            "events_ingested": ingested,
        }

    @staticmethod
    def _parse_output(output: str) -> list[dict[str, Any]]:
        """Parse common YARA CLI output conservatively."""
        matches: list[dict[str, Any]] = []
        current: dict[str, Any] | None = None

        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith("0x") and current is not None:
                current["strings"].append(line)
                continue
            if line.startswith("[") and current is not None:
                current.setdefault("raw_metadata", []).append(line)
                continue

            parts = line.split()
            if not parts:
                continue
            current = {
                "rule": parts[0],
                "namespace": None,
                "tags": [],
                "metadata": {},
                "strings": [],
                "raw": line,
            }
            matches.append(current)

        return matches
