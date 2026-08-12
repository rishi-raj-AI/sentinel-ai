from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Callable

import psutil

ToolFunction = Callable[..., Any]


def list_directory(path: str = ".") -> list[str]:
    target = Path(path).expanduser().resolve()
    return sorted(item.name for item in target.iterdir())


def read_text_file(path: str, max_bytes: int = 1_000_000) -> str:
    target = Path(path).expanduser().resolve()
    if target.stat().st_size > max_bytes:
        raise ValueError(f"File exceeds read limit of {max_bytes} bytes")
    return target.read_text(encoding="utf-8")


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
    "forensic.sha256_file": sha256_file,
    "system.disk_usage": disk_usage,
    "system.info": system_info,
}


def get_tool(name: str) -> ToolFunction:
    try:
        return TOOLS[name]
    except KeyError as exc:
        raise ValueError(f"Unknown or unregistered tool: {name}") from exc
