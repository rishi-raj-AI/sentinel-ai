from __future__ import annotations

import hashlib
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.forensics.case_manager import CaseManager
from app.forensics.chain_of_custody import ChainOfCustody


def sha256_path(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


class EvidenceManager:
    def __init__(self, cases_root: str = "cases") -> None:
        self.cases = CaseManager(cases_root)

    def register(self, case_id: str, source_path: str, *, copy: bool = True) -> dict[str, Any]:
        source = Path(source_path).expanduser().resolve()
        if not source.is_file():
            raise FileNotFoundError(f"Evidence file not found: {source}")

        record = self.cases.load_case(case_id)
        case_dir = self.cases.root / case_id
        evidence_dir = case_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)

        evidence_id = f"E{len(record['evidence']) + 1:04d}"
        destination = evidence_dir / f"{evidence_id}_{source.name}"
        if copy:
            shutil.copy2(source, destination)
        else:
            destination = source

        digest = sha256_path(destination)
        item = {
            "evidence_id": evidence_id,
            "original_path": str(source),
            "stored_path": str(destination.resolve()),
            "filename": source.name,
            "size_bytes": destination.stat().st_size,
            "sha256": digest,
            "registered_at": datetime.now(timezone.utc).isoformat(),
        }
        record["evidence"].append(item)
        self.cases.save_case(record)
        ChainOfCustody(case_dir).append("evidence_registered", item)
        return item

    def verify(self, case_id: str, evidence_id: str | None = None) -> dict[str, Any]:
        record = self.cases.load_case(case_id)
        checks: list[dict[str, Any]] = []
        for item in record["evidence"]:
            if evidence_id and item["evidence_id"] != evidence_id:
                continue
            stored = Path(item["stored_path"])
            actual = sha256_path(stored) if stored.exists() else None
            checks.append({
                "evidence_id": item["evidence_id"],
                "exists": stored.exists(),
                "expected_sha256": item["sha256"],
                "actual_sha256": actual,
                "match": actual == item["sha256"],
            })
        if evidence_id and not checks:
            raise ValueError(f"Evidence not found in {case_id}: {evidence_id}")
        ledger_ok = ChainOfCustody(self.cases.root / case_id).verify()
        return {
            "case_id": case_id,
            "evidence": checks,
            "all_match": bool(checks) and all(item["match"] for item in checks),
            "chain_of_custody_valid": ledger_ok,
        }
