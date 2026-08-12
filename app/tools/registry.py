from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Callable

import psutil

from app.tools.forensics import create_case, register_evidence, show_case, verify_evidence
from app.tools.memory import forget, list_memories, recall, remember

ToolFunction = Callable[..., Any]


def list_directory(path: str = ".") -> list[str]:
    target = Path(path).expanduser().resolve()
    return sorted(item.name for item in target.iterdir())


def read_text_file(path: str, max_bytes: int = 1_000_000) -> str:
    target = Path(path).expanduser().resolve()
    if target.stat().st_size > max_bytes:
        raise ValueError(f"File exceeds read limit of {max_bytes} bytes")
    return target.read_text(encoding="utf-8")


def write_text_file(path: str, content: str, overwrite: bool = False) -> dict[str, Any]:
    target = Path(path).expanduser().resolve()
    if target.exists() and not overwrite:
        raise FileExistsError(f"File already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return {"path": str(target), "bytes_written": len(content.encode("utf-8"))}


def create_directory(path: str) -> dict[str, Any]:
    target = Path(path).expanduser().resolve()
    target.mkdir(parents=True, exist_ok=True)
    return {"path": str(target), "created": True}


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    target = Path(path).expanduser().resolve()
    digest = hashlib.sha256()
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def disk_usage(path: str = "/") -> dict[str, int | float]:
    usage = psutil.disk_usage(str(Path(path).expanduser()))
    return {
        "total": usage.total,
        "used": usage.used,
        "free": usage.free,
        "percent": usage.percent,
    }


def system_info() -> dict[str, Any]:
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory": psutil.virtual_memory()._asdict(),
        "boot_time": psutil.boot_time(),
    }


TOOLS: dict[str, ToolFunction] = {
    "filesystem.list_directory": list_directory,
    "filesystem.read_text_file": read_text_file,
    "filesystem.write_text_file": write_text_file,
    "filesystem.create_directory": create_directory,
    "forensic.sha256_file": sha256_file,
    "forensic.create_case": create_case,
    "forensic.register_evidence": register_evidence,
    "forensic.verify_evidence": verify_evidence,
    "forensic.show_case": show_case,
    "system.disk_usage": disk_usage,
    "system.info": system_info,
    "memory.remember": remember,
    "memory.recall": recall,
    "memory.forget": forget,
    "memory.list": list_memories,
}


def get_tool(name: str) -> ToolFunction:
    try:
        return TOOLS[name]
    except KeyError as exc:
        raise ValueError(f"Unknown or unregistered tool: {name}") from exc
