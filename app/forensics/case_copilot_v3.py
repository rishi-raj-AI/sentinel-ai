from __future__ import annotations

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
    `/api/tags`, resolves the exact installed model name (for example
    `llama3.2:latest` for configured `llama3.2`), and retries once.
    """

    def __init__(self) -> None:
        super().__init__()
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
        rows = response.json().get("models") or []
        installed = [str(row.get("name") or "").strip() for row in rows if row.get("name")]
        if not installed:
            return None

        configured = self.model.strip()
        if configured in installed:
            return configured

        configured_base = configured.split(":", 1)[0]
        same_base = [name for name in installed if name.split(":", 1)[0] == configured_base]
        if len(same_base) == 1:
            return same_base[0]

        latest = f"{configured_base}:latest"
        if latest in installed:
            return latest

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
            if not resolved or resolved == self.model:
                raise
            self.model = resolved
            self.resolved_model = resolved
            return self._complete_ollama_once(endpoint, system_prompt, user_prompt)

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
        result["transport"] = getattr(self.provider, "transport", None)
        result["active_endpoint"] = getattr(self.provider, "active_endpoint", None)
        result["resolved_model"] = getattr(self.provider, "resolved_model", None)
        return result


def install_base_patch() -> None:
    """Patch modules that imported the original copilot class before v3 loads."""
    import app.web.dashboard as dashboard

    dashboard.CaseCopilot = CaseCopilot


__all__ = ["CaseCopilot", "CopilotSource", "ModelProvider", "install_base_patch"]
