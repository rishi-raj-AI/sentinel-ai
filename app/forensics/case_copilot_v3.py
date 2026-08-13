from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.forensics.case_copilot import ModelProvider as BaseModelProvider
from app.forensics.case_copilot_v2 import CaseCopilot as CitationCaseCopilot, CopilotSource


class ModelProvider(BaseModelProvider):
    """Transport-aware model provider with Ollama model auto-resolution.

    Uses the configured OpenAI-compatible endpoint first. If that endpoint
    returns HTTP 404, Sentinel retries Ollama's native `/api/chat` endpoint on
    the same origin. If native Ollama also returns 404, Sentinel queries
    `/api/tags`, resolves the exact installed model name, and retries once.

    Resolution order deliberately prefers Sentinel's persisted local model
    configuration before falling back to same-family or single-model choices.
    This prevents a stale shell environment variable such as ``R-Pilot`` from
    masking a valid model saved by the local setup script.
    """

    def __init__(self) -> None:
        super().__init__()
        self.configured_model: str = self.model
        self.persisted_model: str | None = self._persisted_model_name()
        self.transport: str | None = None
        self.active_endpoint: str | None = None
        self.resolved_model: str | None = None

    @staticmethod
    def _origin_endpoint(endpoint: str, path: str) -> str:
        parsed = urlsplit(endpoint)
        if not parsed.scheme or not parsed.netloc:
            return endpoint
        return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))

    @classmethod
    def _ollama_native_endpoint(cls, endpoint: str) -> str:
        return cls._origin_endpoint(endpoint, "/api/chat")

    @classmethod
    def _ollama_tags_endpoint(cls, endpoint: str) -> str:
        return cls._origin_endpoint(endpoint, "/api/tags")

    @staticmethod
    def _persisted_model_name() -> str | None:
        path = Path(os.getenv("SENTINEL_MODEL_CONFIG", "config/model.json")).expanduser()
        if not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        model = str(payload.get("model") or "").strip()
        return model or None

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _openai_payload(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        return {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
        }

    def _ollama_payload(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        return {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {"temperature": 0.1},
        }

    @staticmethod
    def _parse_openai(body: dict[str, Any]) -> str:
        choices = body.get("choices") or []
        if not choices:
            raise RuntimeError("OpenAI-compatible response contained no choices")
        content = ((choices[0] or {}).get("message") or {}).get("content")
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("OpenAI-compatible response contained no text content")
        return content.strip()

    @staticmethod
    def _parse_ollama(body: dict[str, Any]) -> str:
        content = (body.get("message") or {}).get("content")
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("Ollama response contained no message content")
        return content.strip()

    def _post(self, endpoint: str, payload: dict[str, Any]) -> httpx.Response:
        with httpx.Client(timeout=self.timeout) as client:
            return client.post(endpoint, headers=self._headers(), json=payload)

    def _get(self, endpoint: str) -> httpx.Response:
        with httpx.Client(timeout=self.timeout) as client:
            return client.get(endpoint, headers=self._headers())

    def _resolve_ollama_model(self) -> str | None:
        response = self._get(self._ollama_tags_endpoint(self.endpoint))
        response.raise_for_status()
        body = response.json()
        rows = body.get("models") or []
        installed = [str(row.get("name") or row.get("model") or "").strip() for row in rows if isinstance(row, dict)]
        installed = list(dict.fromkeys(name for name in installed if name))
        if not installed:
            return None

        configured = self.model.strip()
        if configured in installed:
            return configured

        # Provider test doubles and third-party subclasses may not run this
        # class's __init__. Treat missing persisted_model as simply absent.
        persisted = str(getattr(self, "persisted_model", None) or "").strip()
        if persisted:
            if persisted in installed:
                return persisted
            persisted_base = persisted.split(":", 1)[0]
            persisted_matches = [name for name in installed if name.split(":", 1)[0] == persisted_base]
            if len(persisted_matches) == 1:
                return persisted_matches[0]
            persisted_latest = f"{persisted_base}:latest"
            if persisted_latest in installed:
                return persisted_latest

        configured_base = configured.split(":", 1)[0]
        same_base = [name for name in installed if name.split(":", 1)[0] == configured_base]
        if len(same_base) == 1:
            return same_base[0]

        latest = f"{configured_base}:latest"
        if latest in installed:
            return latest

        for preferred in ("llama3.2:latest", "llama3.2"):
            if preferred in installed:
                return preferred

        if len(installed) == 1:
            return installed[0]

        return None

    def _complete_openai(self, system_prompt: str, user_prompt: str) -> str:
        response = self._post(self.endpoint, self._openai_payload(system_prompt, user_prompt))
        response.raise_for_status()
        self.transport = "openai-compatible"
        self.active_endpoint = self.endpoint
        return self._parse_openai(response.json())

    def _complete_ollama_once(self, endpoint: str, system_prompt: str, user_prompt: str) -> str:
        response = self._post(endpoint, self._ollama_payload(system_prompt, user_prompt))
        response.raise_for_status()
        self.transport = "ollama-native"
        self.active_endpoint = endpoint
        return self._parse_ollama(response.json())

    def _complete_ollama(self, system_prompt: str, user_prompt: str) -> str:
        endpoint = self._ollama_native_endpoint(self.endpoint)
        try:
            return self._complete_ollama_once(endpoint, system_prompt, user_prompt)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise
            resolved = self._resolve_ollama_model()
            if not resolved:
                raise RuntimeError(
                    f"Ollama returned 404 for configured model '{self.model}' and no installed model could be resolved"
                ) from exc
            if resolved != self.model:
                self.model = resolved
                self.resolved_model = resolved
                return self._complete_ollama_once(endpoint, system_prompt, user_prompt)
            raise

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        if not self.configured:
            raise RuntimeError("No model provider configured")

        if self.transport == "ollama-native":
            return self._complete_ollama(system_prompt, user_prompt)
        if self.transport == "openai-compatible":
            return self._complete_openai(system_prompt, user_prompt)

        if urlsplit(self.endpoint).path.rstrip("/") == "/api/chat":
            return self._complete_ollama(system_prompt, user_prompt)

        try:
            return self._complete_openai(system_prompt, user_prompt)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise
            return self._complete_ollama(system_prompt, user_prompt)


class CaseCopilot(CitationCaseCopilot):
    def __init__(self, case_dir, *, sigma_rules: str = "rules/sigma", provider: ModelProvider | None = None) -> None:
        super().__init__(case_dir, sigma_rules=sigma_rules, provider=provider or ModelProvider())

    def answer(self, question: str, *, max_sources: int = 12) -> dict[str, Any]:
        result = super().answer(question, max_sources=max_sources)
        result["configured_model"] = getattr(self.provider, "configured_model", getattr(self.provider, "model", None))
        result["persisted_model"] = getattr(self.provider, "persisted_model", None)
        result["transport"] = getattr(self.provider, "transport", None)
        result["active_endpoint"] = getattr(self.provider, "active_endpoint", None)
        result["resolved_model"] = getattr(self.provider, "resolved_model", None)
        if result.get("mode") == "model":
            result["model"] = getattr(self.provider, "model", result.get("model"))
        return result


def install_base_patch() -> None:
    """Patch modules that imported the original copilot class before v3 loads."""
    import app.web.dashboard as dashboard

    dashboard.CaseCopilot = CaseCopilot


__all__ = ["CaseCopilot", "CopilotSource", "ModelProvider", "install_base_patch"]
