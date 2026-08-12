from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    tool TEXT NOT NULL,
    arguments TEXT NOT NULL,
    risk_level INTEGER NOT NULL,
    success INTEGER NOT NULL,
    output_hash TEXT,
    error TEXT
)
"""


class AuditLogger:
    def __init__(self, db_path: str = "logs/audit.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(SCHEMA)

    def record(
        self,
        *,
        tool: str,
        arguments: dict[str, Any],
        risk_level: int,
        success: bool,
        output: Any = None,
        error: str | None = None,
    ) -> None:
        output_hash = None
        if output is not None:
            payload = json.dumps(output, sort_keys=True, default=str).encode("utf-8")
            output_hash = hashlib.sha256(payload).hexdigest()

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO actions
                (timestamp, tool, arguments, risk_level, success, output_hash, error)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    tool,
                    json.dumps(arguments, sort_keys=True, default=str),
                    risk_level,
                    int(success),
                    output_hash,
                    error,
                ),
            )
