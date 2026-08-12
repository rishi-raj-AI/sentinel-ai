from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

import httpx

from app.forensics.attack_mapping import AttackMappingEngine
from app.forensics.case_reasoning import CaseReasoningEngine
from app.forensics.network_intelligence import NetworkIntelligenceEngine
from app.forensics.sigma_engine import SigmaEngine
from app.forensics.timeline import TimelineStore


@dataclass(slots=True)
class CopilotSource:
    source_id: str
    kind: str
    title: str
    text: str
    evidence_id: str | None = None
    timestamp: str | None = None
    metadata: dict[str, Any] | None = None


class ModelProvider:
    """Optional OpenAI-compatible chat-completions provider.

    Configuration can come from environment variables or from the local
    `config/model.json` file written by Sentinel's setup script. Placeholder
    environment values such as YOUR_PORT are ignored so they cannot override a
    valid persisted local configuration.
    """

    DEFAULT_CONFIG = Path("config/model.json")

    def __init__(self) -> None:
        config = self._load_config()
        env_endpoint = os.getenv("SENTINEL_MODEL_ENDPOINT", "").strip()
        env_model = os.getenv("SENTINEL_MODEL_NAME", "").strip()
        env_key = os.getenv("SENTINEL_MODEL_API_KEY", "").strip()

        self.endpoint = env_endpoint if self._usable(env_endpoint) else str(config.get("endpoint") or "").strip()
        self.model = env_model if self._usable(env_model) else str(config.get("model") or "").strip()
        self.api_key = env_key if self._usable(env_key) else str(config.get("api_key") or "").strip()
        timeout_raw = os.getenv("SENTINEL_MODEL_TIMEOUT", str(config.get("timeout") or "30"))
        self.timeout = float(timeout_raw)
        self.config_source = "environment" if self._usable(env_endpoint) and self._usable(env_model) else ("config_file" if self.endpoint and self.model else "none")

    @classmethod
    def _load_config(cls) -> dict[str, Any]:
        path = Path(os.getenv("SENTINEL_MODEL_CONFIG", str(cls.DEFAULT_CONFIG))).expanduser()
        if not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _usable(value: str) -> bool:
        if not value:
            return False
        upper = value.upper()
        return not any(marker in upper for marker in ("YOUR_PORT", "YOUR_MODEL", "YOUR_API", "PLACEHOLDER"))

    @property
    def configured(self) -> bool:
        return bool(self.endpoint and self.model)

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        if not self.configured:
            raise RuntimeError("No model provider configured")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
        }
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(self.endpoint, headers=headers, json=payload)
            response.raise_for_status()
            body = response.json()
        choices = body.get("choices") or []
        if not choices:
            raise RuntimeError("Model response contained no choices")
        content = ((choices[0] or {}).get("message") or {}).get("content")
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("Model response contained no text content")
        return content.strip()


class CaseCopilot:
    """Evidence-grounded natural-language copilot for a Sentinel case."""

    STOPWORDS = {
        "the", "a", "an", "and", "or", "to", "of", "in", "on", "for", "is", "are",
        "was", "were", "what", "which", "who", "how", "why", "should", "i", "we", "me",
        "my", "this", "that", "with", "from", "about", "case", "show", "tell", "please",
    }

    def __init__(self, case_dir: str | Path, *, sigma_rules: str = "rules/sigma", provider: ModelProvider | None = None) -> None:
        self.case_dir = Path(case_dir)
        self.sigma_rules = sigma_rules
        self.timeline = TimelineStore(case_dir)
        self.provider = provider or ModelProvider()

    @staticmethod
    def _case_record(case_dir: Path) -> dict[str, Any]:
        path = case_dir / "case.json"
        if not path.is_file():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    @classmethod
    def _terms(cls, text: str) -> set[str]:
        words = re.findall(r"[a-zA-Z0-9_.:-]{2,}", text.lower())
        return {word for word in words if word not in cls.STOPWORDS}

    @staticmethod
    def _source_blob(source: CopilotSource) -> str:
        return f"{source.source_id} {source.kind} {source.title} {source.text} {source.evidence_id or ''}".lower()

    def _collect_sources(self, max_items: int = 300) -> list[CopilotSource]:
        sources: list[CopilotSource] = []
        case = self._case_record(self.case_dir)
        for item in case.get("evidence", []):
            eid = str(item.get("evidence_id") or "")
            if not eid:
                continue
            sources.append(CopilotSource(
                source_id=f"EVIDENCE:{eid}",
                kind="evidence",
                title=f"{eid} {item.get('filename') or ''}".strip(),
                text=f"Registered evidence {eid}; filename={item.get('filename')}; sha256={item.get('sha256')}; size={item.get('size_bytes')}",
                evidence_id=eid,
                timestamp=item.get("registered_at"),
                metadata={"sha256": item.get("sha256"), "filename": item.get("filename")},
            ))

        sigma = SigmaEngine(self.case_dir).analyze(self.sigma_rules, max_detections=100)
        for idx, row in enumerate(sigma.get("detections", []), start=1):
            sid = f"SIGMA:{row.get('rule_id')}:{idx}"
            sources.append(CopilotSource(
                source_id=sid,
                kind="sigma",
                title=str(row.get("title") or row.get("rule_id") or "Sigma detection"),
                text=f"Sigma detection level={row.get('level')} evidence={row.get('evidence_id')} matched={row.get('matched_selections')} tags={row.get('tags')}",
                evidence_id=row.get("evidence_id"),
                timestamp=row.get("event_timestamp"),
                metadata={"rule_id": row.get("rule_id"), "level": row.get("level"), "tags": row.get("tags") or []},
            ))

        yara_seen: dict[tuple[str, str], dict[str, Any]] = {}
        events = self.timeline.read()
        for event in events:
            if event.get("source") != "yara" and event.get("event_type") != "yara_match":
                continue
            details = event.get("details") or {}
            key = (str(event.get("evidence_id") or ""), str(details.get("rule") or "unknown"))
            row = yara_seen.setdefault(key, {"count": 0, "first": event.get("timestamp"), "last": event.get("timestamp")})
            row["count"] += 1
            stamp = event.get("timestamp")
            if stamp and (not row["first"] or stamp < row["first"]):
                row["first"] = stamp
            if stamp and (not row["last"] or stamp > row["last"]):
                row["last"] = stamp
        for (eid, rule), row in yara_seen.items():
            sources.append(CopilotSource(
                source_id=f"YARA:{eid}:{rule}",
                kind="yara",
                title=f"YARA {rule}",
                text=f"YARA rule {rule} matched evidence {eid} {row['count']} time(s); first_seen={row['first']} last_seen={row['last']}",
                evidence_id=eid or None,
                timestamp=row["last"],
                metadata={"rule": rule, "match_count": row["count"]},
            ))

        attack = AttackMappingEngine(self.case_dir).analyze(max_candidates=100)
        for idx, row in enumerate(attack.get("candidates", []), start=1):
            sources.append(CopilotSource(
                source_id=f"ATTACK:{row.get('technique_id')}:{idx}",
                kind="attack",
                title=f"{row.get('technique_id')} {row.get('technique_name')}",
                text=f"ATT&CK candidate tactic={row.get('tactic')} confidence={row.get('confidence')}; reason={row.get('reason')}",
                metadata={"technique_id": row.get("technique_id"), "confidence": row.get("confidence")},
            ))

        network = NetworkIntelligenceEngine(self.case_dir).analyze(max_flows=100)
        for idx, flow in enumerate(network.get("flows", []), start=1):
            proto = flow.get("protocol") or "/".join(flow.get("protocols") or []) or "network"
            sources.append(CopilotSource(
                source_id=f"FLOW:{idx}",
                kind="network",
                title=f"{proto} {flow.get('src')}:{flow.get('src_port')} -> {flow.get('dst')}:{flow.get('dst_port')}",
                text=f"Network flow protocol={proto}; src={flow.get('src')}:{flow.get('src_port')}; dst={flow.get('dst')}:{flow.get('dst_port')}; packets={flow.get('packet_count')}; evidence={flow.get('evidence_ids')}; dst_scope={flow.get('dst_scope')}",
                evidence_id=(flow.get("evidence_ids") or [None])[0],
                timestamp=flow.get("last_seen"),
                metadata={"src": flow.get("src"), "dst": flow.get("dst"), "dst_port": flow.get("dst_port")},
            ))

        for idx, event in enumerate(events[-max_items:], start=1):
            sources.append(CopilotSource(
                source_id=f"TIMELINE:{idx}",
                kind="timeline",
                title=str(event.get("summary") or event.get("event_type") or "event"),
                text=f"timestamp={event.get('timestamp')} source={event.get('source')} type={event.get('event_type')} summary={event.get('summary')} details={event.get('details')}",
                evidence_id=event.get("evidence_id"),
                timestamp=event.get("timestamp"),
                metadata={"source": event.get("source"), "event_type": event.get("event_type")},
            ))

        brief = CaseReasoningEngine(self.case_dir, sigma_rules=self.sigma_rules).build(max_items=25)
        sources.append(CopilotSource(
            source_id="BRIEF:CURRENT",
            kind="brief",
            title=str(brief.get("headline") or "Current case brief"),
            text=json.dumps({
                "headline": brief.get("headline"),
                "confidence": brief.get("confidence"),
                "collection_gaps": brief.get("collection_gaps"),
                "recommended_actions": brief.get("recommended_actions"),
                "hypotheses": brief.get("hypotheses"),
            }, ensure_ascii=True),
            metadata={"confidence": brief.get("confidence")},
        ))
        return sources

    def retrieve(self, question: str, *, limit: int = 12) -> list[CopilotSource]:
        terms = self._terms(question)
        sources = self._collect_sources()
        type_boosts: set[str] = set()
        q = question.lower()
        if any(x in q for x in ("network", "ip", "port", "dns", "flow")):
            type_boosts.add("network")
        if any(x in q for x in ("sigma", "detection", "alert")):
            type_boosts.add("sigma")
        if "yara" in q or "malware" in q:
            type_boosts.add("yara")
        if any(x in q for x in ("attack", "mitre", "technique")):
            type_boosts.add("attack")
        if any(x in q for x in ("evidence", "hash", "file")):
            type_boosts.add("evidence")
        if any(x in q for x in ("next", "gap", "missing", "recommend", "summary", "assessment")):
            type_boosts.add("brief")

        scored: list[tuple[int, CopilotSource]] = []
        ip_hits = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", question)
        for source in sources:
            blob = self._source_blob(source)
            overlap = sum(1 for term in terms if term in blob)
            score = overlap * 4
            if source.kind in type_boosts:
                score += 7
            if source.kind in {"sigma", "yara", "attack"}:
                score += 2
            if source.evidence_id and source.evidence_id.lower() in q:
                score += 12
            if any(ip in blob for ip in ip_hits):
                score += 12
            scored.append((score, source))

        scored.sort(key=lambda item: (item[0], item[1].timestamp or ""), reverse=True)
        selected = [source for score, source in scored if score > 0][:limit]
        if not selected:
            selected = [source for _, source in scored if source.kind in {"brief", "sigma", "yara", "network"}][:limit]
        return selected

    @staticmethod
    def _deterministic_answer(question: str, sources: list[CopilotSource]) -> str:
        if not sources:
            return "I could not find supporting case evidence for that question."
        lines = ["Based on the currently ingested case evidence:"]
        for source in sources[:6]:
            lines.append(f"- [{source.source_id}] {source.title}: {source.text}")
        lines.append("This is investigative decision support; validate detections and hypotheses against the preserved evidence before escalation.")
        return "\n".join(lines)

    @staticmethod
    def _system_prompt() -> str:
        return (
            "You are Sentinel's read-only forensic case copilot. Answer only from the supplied case sources. "
            "Do not invent facts, compromise verdicts, attribution, or missing telemetry. Distinguish observations from inference. "
            "Every material factual claim must cite at least one supplied source ID in square brackets, for example [EVIDENCE:E0003]. "
            "If the sources are insufficient, say so. Keep answers concise and investigator-oriented."
        )

    @staticmethod
    def _user_prompt(question: str, sources: list[CopilotSource]) -> str:
        rendered = "\n\n".join(
            f"SOURCE {source.source_id}\nKIND: {source.kind}\nTITLE: {source.title}\nTEXT: {source.text}"
            for source in sources
        )
        return f"QUESTION:\n{question}\n\nCASE SOURCES:\n{rendered}"

    @staticmethod
    def _citations_are_grounded(answer: str, sources: list[CopilotSource]) -> bool:
        cited = set(re.findall(r"\[([^\[\]]+:[^\[\]]+)\]", answer))
        allowed = {source.source_id for source in sources}
        return bool(cited) and cited.issubset(allowed)

    def answer(self, question: str, *, max_sources: int = 12) -> dict[str, Any]:
        text = question.strip()
        if not text:
            return {"answer": "Ask a question about the current case.", "sources": [], "mode": "none", "model": None}
        sources = self.retrieve(text, limit=max_sources)
        mode = "deterministic"
        model_name: str | None = None
        error: str | None = None
        if self.provider.configured:
            try:
                answer = self.provider.complete(self._system_prompt(), self._user_prompt(text, sources))
                if not self._citations_are_grounded(answer, sources):
                    raise RuntimeError("Model answer did not contain only valid retrieved Sentinel citations")
                mode = "model"
                model_name = self.provider.model
            except Exception as exc:
                error = f"model_fallback: {type(exc).__name__}: {exc}"
                answer = self._deterministic_answer(text, sources)
        else:
            answer = self._deterministic_answer(text, sources)

        return {
            "answer": answer,
            "mode": mode,
            "model": model_name,
            "sources": [asdict(source) for source in sources],
            "source_count": len(sources),
            "provider_error": error,
            "grounding": "Answer constrained to retrieved Sentinel case sources.",
        }
