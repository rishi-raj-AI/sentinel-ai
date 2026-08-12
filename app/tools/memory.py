from __future__ import annotations

from typing import Any

from app.memory.store import MemoryStore

_store = MemoryStore()


def remember(key: str, value: Any, category: str = "personal") -> dict[str, Any]:
    _store.set(key, value, category)
    return {"key": key, "value": value, "category": category}


def recall(key: str) -> Any | None:
    return _store.get(key)


def forget(key: str) -> dict[str, Any]:
    return {"key": key, "forgotten": _store.forget(key)}


def list_memories(category: str | None = None) -> list[dict[str, Any]]:
    return _store.list(category)
