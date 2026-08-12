from __future__ import annotations

import fnmatch
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

import yaml

from app.forensics.timeline import TimelineStore


@dataclass(slots=True)
class SigmaDetection:
    rule_id: str
    title: str
    level: str
    event_timestamp: str | None
    event_source: str | None
    event_type: str | None
    evidence_id: str | None
    matched_selections: list[str]
    event: dict[str, Any]
    tags: list[str]


class SigmaEngine:
    """Evaluate a conservative Sigma-compatible subset against Sentinel events.

    Supported detection features:
      * mapping selections (AND between fields)
      * list values (OR; `|all` changes list semantics to AND)
      * `contains`, `startswith`, `endswith`, `exists`, `re`
      * simple conditions using selection names, `and`, `or`, `not`
      * `1 of them`, `all of them`, `1/all of prefix*`

    Unsupported constructs fail closed rather than being guessed.
    """

    def __init__(self, case_dir: str | Path) -> None:
        self.case_dir = Path(case_dir)
        self.timeline = TimelineStore(case_dir)

    def analyze(self, rule_path: str, *, max_detections: int = 100) -> dict[str, Any]:
        if max_detections < 1 or max_detections > 5000:
            raise ValueError("max_detections must be between 1 and 5000")
        rules = self._load_rules(rule_path)
        events = self.timeline.read()
        detections: list[SigmaDetection] = []
        evaluated = 0

        for rule in rules:
            detection = rule.get("detection") or {}
            condition = str(detection.get("condition") or "").strip()
            selections = {k: v for k, v in detection.items() if k != "condition" and not str(k).startswith("_")}
            if not condition or not selections:
                continue

            for event in events:
                if len(detections) >= max_detections:
                    break
                if not self._logsource_matches(rule.get("logsource") or {}, event):
                    continue
                evaluated += 1
                selection_results = {name: self._selection_matches(spec, event) for name, spec in selections.items()}
                if not self._condition_matches(condition, selection_results):
                    continue
                detections.append(
                    SigmaDetection(
                        rule_id=str(rule.get("id") or rule.get("title") or "unnamed-rule"),
                        title=str(rule.get("title") or "Untitled Sigma rule"),
                        level=str(rule.get("level") or "medium").lower(),
                        event_timestamp=event.get("timestamp"),
                        event_source=event.get("source"),
                        event_type=event.get("event_type"),
                        evidence_id=event.get("evidence_id"),
                        matched_selections=sorted(name for name, matched in selection_results.items() if matched),
                        event=event,
                        tags=[str(tag) for tag in (rule.get("tags") or [])],
                    )
                )
            if len(detections) >= max_detections:
                break

        levels = Counter(item.level for item in detections)
        rule_counts = Counter(item.rule_id for item in detections)
        return {
            "rule_count": len(rules),
            "events_considered": evaluated,
            "detection_count": len(detections),
            "detections": [asdict(item) for item in detections],
            "summary": {
                "by_level": dict(levels),
                "by_rule": dict(rule_counts),
                "truncated": len(detections) >= max_detections,
                "engine": "sentinel-sigma-subset-v1",
            },
        }

    @staticmethod
    def _load_rules(path: str) -> list[dict[str, Any]]:
        target = Path(path).expanduser().resolve()
        if not target.exists():
            raise FileNotFoundError(f"Sigma rule path not found: {target}")
        files = sorted(target.glob("*.yml")) + sorted(target.glob("*.yaml")) if target.is_dir() else [target]
        rules: list[dict[str, Any]] = []
        for file in files:
            with file.open("r", encoding="utf-8") as handle:
                for document in yaml.safe_load_all(handle):
                    if isinstance(document, dict):
                        rules.append(document)
        return rules

    @staticmethod
    def _event_fields(event: dict[str, Any]) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        fields.update(event.get("details") or {})
        fields.update({
            "timestamp": event.get("timestamp"),
            "source": event.get("source"),
            "event_type": event.get("event_type"),
            "summary": event.get("summary"),
            "evidence_id": event.get("evidence_id"),
        })
        aliases = {
            "EventID": fields.get("event_id") or fields.get("EventID"),
            "Image": fields.get("Image") or fields.get("image") or fields.get("NewProcessName") or fields.get("process"),
            "CommandLine": fields.get("CommandLine") or fields.get("command_line") or fields.get("ProcessCommandLine"),
            "ParentImage": fields.get("ParentImage") or fields.get("parent_image") or fields.get("ParentProcessName"),
            "DestinationIp": fields.get("DestinationIp") or fields.get("dst"),
            "DestinationPort": fields.get("DestinationPort") or fields.get("tcp_dstport") or fields.get("udp_dstport"),
            "SourceIp": fields.get("SourceIp") or fields.get("src"),
        }
        for key, value in aliases.items():
            if value not in (None, ""):
                fields[key] = value
        return fields

    @classmethod
    def _selection_matches(cls, spec: Any, event: dict[str, Any]) -> bool:
        fields = cls._event_fields(event)
        if isinstance(spec, list):
            return any(cls._selection_matches(item, event) for item in spec)
        if isinstance(spec, str):
            haystack = " ".join(str(v) for v in fields.values() if v not in (None, ""))
            return cls._wildcard_match(haystack, spec)
        if not isinstance(spec, dict):
            return False
        return all(cls._field_matches(fields, key, expected) for key, expected in spec.items())

    @classmethod
    def _field_matches(cls, fields: dict[str, Any], raw_key: str, expected: Any) -> bool:
        parts = str(raw_key).split("|")
        field = parts[0]
        modifiers = parts[1:]
        actual = fields.get(field)
        if "exists" in modifiers:
            want = bool(expected)
            return (actual not in (None, "")) is want
        values = expected if isinstance(expected, list) else [expected]
        results = [cls._value_matches(actual, value, modifiers) for value in values]
        return all(results) if "all" in modifiers else any(results)

    @staticmethod
    def _value_matches(actual: Any, expected: Any, modifiers: list[str]) -> bool:
        if actual is None:
            return expected is None
        a = str(actual)
        e = "" if expected is None else str(expected)
        lower_mods = [m.lower() for m in modifiers]
        if "re" in lower_mods:
            import re
            try:
                return re.search(e, a) is not None
            except re.error:
                return False
        a_cmp, e_cmp = a.casefold(), e.casefold()
        if "contains" in lower_mods:
            return e_cmp in a_cmp
        if "startswith" in lower_mods:
            return a_cmp.startswith(e_cmp)
        if "endswith" in lower_mods:
            return a_cmp.endswith(e_cmp)
        return SigmaEngine._wildcard_match(a, e)

    @staticmethod
    def _wildcard_match(actual: str, expected: str) -> bool:
        return fnmatch.fnmatchcase(actual.casefold(), expected.casefold())

    @staticmethod
    def _condition_matches(condition: str, results: dict[str, bool]) -> bool:
        text = " ".join(condition.strip().split()).lower()
        names = list(results)
        if text == "1 of them":
            return any(results.values())
        if text == "all of them":
            return all(results.values()) if results else False
        for quantifier in ("1 of ", "all of "):
            if text.startswith(quantifier) and text.endswith("*"):
                prefix = text[len(quantifier):-1]
                subset = [value for name, value in results.items() if name.lower().startswith(prefix)]
                return (any(subset) if quantifier.startswith("1") else all(subset)) if subset else False

        # Fail closed on parentheses/advanced Sigma expressions in v1.
        if any(token in text for token in ("(", ")", "near", "|")):
            return False
        tokens = text.split()
        if not tokens:
            return False

        def value(token: str) -> bool:
            return bool(results.get(token, False))

        current: bool | None = None
        op = "or"
        negate = False
        for token in tokens:
            if token in {"and", "or"}:
                op = token
                continue
            if token == "not":
                negate = True
                continue
            item = value(token)
            if negate:
                item = not item
                negate = False
            if current is None:
                current = item
            elif op == "and":
                current = current and item
            else:
                current = current or item
        return bool(current)

    @staticmethod
    def _logsource_matches(logsource: dict[str, Any], event: dict[str, Any]) -> bool:
        product = str(logsource.get("product") or "").lower()
        category = str(logsource.get("category") or "").lower()
        service = str(logsource.get("service") or "").lower()
        source = str(event.get("source") or "").lower()
        event_type = str(event.get("event_type") or "").lower()
        details = event.get("details") or {}
        provider = str(details.get("provider") or "").lower()
        channel = str(details.get("channel") or "").lower()

        if product == "windows" and source != "evtx":
            return False
        if product in {"macos", "macosx"} and source != "macos_unified_log":
            return False
        if category == "process_creation" and event_type != "process":
            return False
        if category == "network_connection" and event_type != "network":
            return False
        if category == "file_event" and event_type != "file":
            return False
        if service and service not in provider and service not in channel:
            return False
        return True
