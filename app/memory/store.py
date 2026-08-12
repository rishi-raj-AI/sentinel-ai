from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class MemoryStore:
    def __init__(self, db_path: str = "logs/memory.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_db(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS memories (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    category TEXT NOT NULL DEFAULT 'personal',
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def set(self, key: str, value: Any, category: str = "personal") -> None:
        encoded = json.dumps(value, ensure_ascii=False)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO memories (key, value, category, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    category = excluded.category,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (key, encoded, category),
            )

    def get(self, key: str) -> Any | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM memories WHERE key = ?", (key,)
            ).fetchone()
        return None if row is None else json.loads(row["value"])

    def forget(self, key: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM memories WHERE key = ?", (key,))
        return cursor.rowcount > 0

    def list(self, category: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT key, value, category, updated_at FROM memories"
        params: tuple[Any, ...] = ()
        if category is not None:
            query += " WHERE category = ?"
            params = (category,)
        query += " ORDER BY key"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [
            {
                "key": row["key"],
                "value": json.loads(row["value"]),
                "category": row["category"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]
