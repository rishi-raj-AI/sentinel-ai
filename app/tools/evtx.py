from __future__ import annotations

import hashlib
import urllib.request
from pathlib import Path

from app.forensics.case_manager import CaseManager
from app.forensics.evidence import EvidenceManager
from app.forensics.evtx_adapter import EvtxAdapter


SAMPLE_EVTX_URL = "https://raw.githubusercontent.com/williballenthin/python-evtx/master/tests/data/issue_38.evtx"
SAMPLE_EVTX_SIZE = 69632


def evtx_status():
    return EvtxAdapter.status()


def create_sample_evtx(path: str = "workspace/sample.evtx"):
    """Download a known-good public EVTX fixture from python-evtx's test corpus."""
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)

    with urllib.request.urlopen(SAMPLE_EVTX_URL, timeout=30) as response:
        payload = response.read()

    if len(payload) != SAMPLE_EVTX_SIZE:
        raise RuntimeError(f"Unexpected EVTX fixture size: {len(payload)} bytes")
    if payload[:7] != b"ElfFile":
        raise RuntimeError("Downloaded fixture does not have a valid EVTX ElfFile signature")

    target.write_bytes(payload)
    return {
        "path": str(target),
        "bytes_written": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "source": "python-evtx upstream test fixture issue_38.evtx",
        "evtx_signature_valid": True,
    }


def evtx_analyze_evidence(case_id: str, evidence_id: str, max_events: int = 5000):
    verification = EvidenceManager().verify(case_id=case_id, evidence_id=evidence_id)
    if not verification.get("all_match") or not verification.get("chain_of_custody_valid"):
        raise RuntimeError(f"Evidence integrity verification failed for {case_id}/{evidence_id}")

    record = CaseManager().load_case(case_id)
    item = next((row for row in record.get("evidence", []) if row.get("evidence_id") == evidence_id), None)
    if item is None:
        raise ValueError(f"Evidence not found in {case_id}: {evidence_id}")

    stored_path = Path(item["stored_path"]).resolve()
    if not stored_path.is_file():
        raise FileNotFoundError(f"Stored evidence file not found: {stored_path}")

    case_dir = CaseManager().root / case_id
    result = EvtxAdapter(case_dir).analyze(str(stored_path), evidence_id=evidence_id, max_events=max_events)
    result.update({
        "case_id": case_id,
        "evidence_id": evidence_id,
        "evidence_sha256_verified": True,
        "chain_of_custody_valid": True,
    })
    return result
