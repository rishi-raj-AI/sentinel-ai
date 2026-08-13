from __future__ import annotations

import hashlib
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from app.enterprise.reasoning_v2 import InvestigationReasoningService
from app.enterprise.workspace import RBAC
from app.forensics.case_copilot_v6 import CaseCopilot
from app.soc.core import (
    AgentFinding,
    CounterEvidenceAgent as BaseCounterEvidenceAgent,
    DetectionAnalystAgent,
    MemoryAnalystAgent,
    NetworkAnalystAgent,
    SOCSupervisor as BaseSOCSupervisor,
    ThreatHunterAgent,
)


class CounterEvidenceAgent(BaseCounterEvidenceAgent):
    """Precision-ranked counter-evidence specialist."""

    def run(self, objective: str) -> AgentFinding:
        service = InvestigationReasoningService(self.case_dir)
        keywords = ["test", "validation", "update", "system", "benign", "normal"]
        rows = service.counter_evidence(keywords, limit=40)
        contradicting = [str(row.get("id") or row.get("label")) for row in rows[:20]]
        confidence, confidence_detail = service.counter_evidence_confidence(rows)
        top = [
            {
                "id": row.get("id"),
                "type": row.get("type"),
                "relevance_score": row.get("relevance_score"),
                "matched_terms": row.get("matched_terms"),
            }
            for row in rows[:10]
        ]
        return AgentFinding(
            self.name,
            self.specialty,
            f"Ranked {len(rows)} alternative/contradicting graph candidate(s) by forensic relevance.",
            confidence,
            [],
            contradicting,
            [],
            ["Review the highest-relevance counter-evidence before escalating any compromise hypothesis."],
            {
                "counter_evidence_candidate_count": len(rows),
                "keywords": keywords,
                "confidence_method": confidence_detail,
                "top_ranked_candidates": top,
            },
        )


class SOCSupervisor(BaseSOCSupervisor):
    """Phase 5.1 supervisor with precision counter-evidence and strict synthesis semantics."""

    VERSION = "5.1"
    AGENT_TYPES = (
        NetworkAnalystAgent,
        DetectionAnalystAgent,
        MemoryAnalystAgent,
        ThreatHunterAgent,
        CounterEvidenceAgent,
    )

    STRICT_SYNTHESIS_RULES = (
        "Use only retrieved Sentinel source IDs as citations; never cite agent names. "
        "A collection gap is only missing telemetry: never infer malware absence, presence, infection state, or evasion from missing memory or other absent evidence. "
        "An unusual port or flow is an observation requiring correlation; it does not by itself indicate malware, C2, compromise, or malicious intent. "
        "A Sigma or YARA match proves a rule match only. A test/validation-named rule must not be described as a malware signature unless retrieved rule metadata explicitly establishes that. "
        "Counter-evidence is alternative context, not automatic proof of benignness. "
        "State uncertainty explicitly and prefer fewer supported claims over speculative explanations."
    )

    def run(self, objective: str, *, role: str = "analyst", persist: bool = True) -> dict[str, Any]:
        RBAC.require(role, "job.run")
        objective = objective.strip()
        if not objective:
            raise ValueError("SOC objective is required")

        started = self._now()
        findings: list[AgentFinding] = []
        transcript: list[dict[str, Any]] = []
        for agent_type in self.AGENT_TYPES:
            finding = agent_type(self.case_dir, sigma_rules=self.sigma_rules).run(objective)
            findings.append(finding)
            transcript.append({
                "timestamp": self._now(),
                "agent": finding.agent,
                "event": "analysis.completed",
                "finding": asdict(finding),
            })

        supporting = list(dict.fromkeys(item for finding in findings for item in finding.supporting))
        contradicting = list(dict.fromkeys(item for finding in findings for item in finding.contradicting))
        gaps = list(dict.fromkeys(item for finding in findings for item in finding.gaps))
        agent_mean = round(sum(finding.confidence for finding in findings) / max(1, len(findings)), 3)
        quality = max(0.45, min(0.95, agent_mean))
        scored = InvestigationReasoningService(self.case_dir).score_hypothesis(
            "The observed case signals warrant escalation for potential malicious activity.",
            supporting=supporting,
            contradicting=contradicting,
            gaps=gaps,
            source_quality=quality,
        )

        specialist_digest = "\n".join(
            f"- {finding.agent}: {finding.summary}; confidence={finding.confidence:.3f}; "
            f"support={finding.supporting[:8]}; counter={finding.contradicting[:8]}; gaps={finding.gaps[:5]}"
            for finding in findings
        )
        synthesis = CaseCopilot(self.case_dir, sigma_rules=self.sigma_rules).answer(
            f"SOC objective: {objective}.\n\nSPECIALIST DIGEST (context only; agent names are not source IDs):\n{specialist_digest}\n\n"
            f"MANDATORY REASONING RULES:\n{self.STRICT_SYNTHESIS_RULES}\n\n"
            "Return only: strongest supported observations; meaningful disagreements/counter-evidence; collection gaps; and next authorized investigative actions.",
            max_sources=16,
        )
        transcript.append({
            "timestamp": self._now(),
            "agent": "soc-supervisor",
            "event": "synthesis.completed",
            "mode": synthesis.get("mode"),
            "provider_error": synthesis.get("provider_error"),
        })

        seed = f"{started}|{self.case_dir.name}|{objective}|5.1".encode()
        run_id = f"SOC-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{hashlib.sha256(seed).hexdigest()[:8]}"
        result = {
            "version": self.VERSION,
            "run_id": run_id,
            "case_id": self.case_dir.name,
            "objective": objective,
            "started_at": started,
            "completed_at": self._now(),
            "mode": "read-only-multi-agent-analysis",
            "agents": [asdict(finding) for finding in findings],
            "agent_count": len(findings),
            "agent_mean_confidence": agent_mean,
            "supervisor_hypothesis": asdict(scored),
            "supporting_evidence": supporting,
            "counter_evidence": contradicting,
            "collection_gaps": gaps,
            "recommendations": list(dict.fromkeys(item for finding in findings for item in finding.recommendations)),
            "synthesis": synthesis,
            "synthesis_contract": {
                "missing_evidence_is_not_evidence_of_absence_or_evasion": True,
                "unusual_network_activity_does_not_imply_maliciousness": True,
                "test_detection_does_not_imply_malware_signature": True,
                "agent_names_are_not_citations": True,
                "claim_verifier_remains_authoritative": True,
            },
            "transcript": transcript,
            "guardrails": {
                "read_only": True,
                "evidence_acquisition": False,
                "endpoint_remediation": False,
                "compromise_verdict_requires_evidence": True,
                "specialist_disagreement_preserved": True,
            },
        }
        if persist:
            result["artifacts"] = self._persist(result)
        return result


__all__ = ["CounterEvidenceAgent", "SOCSupervisor"]
