from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.forensics.case_copilot import ModelProvider as BaseModelProvider
from app.forensics.case_copilot_v2 import CaseCopilot as CitationCaseCopilot, CopilotSource


class ModelProvider(BaseModelProvider):
    """Transport-aware model provider.

    Uses the configured OpenAI-compatible endpoint first. If that endpoint
    returns HTTP 404, Sentinel automatically retries Ollama's native `/api/chat`
    endpoint on the same scheme/host/port. The successful transport is cached on
    the provider instance so later requests avoid probing both routes.
    """

    def __init__(self) -> None:
        super().__init__()
        self.transport: str | None = None
        self.active_endpoint: str | None = None

    @staticmethod
    def _ollama_native_endpoint(endpoint: str) -> str:
        parsed = urlsplit(endpoint)
        if not parsed.scheme or not parsed.netloc:
            return endpoint
        return urlunsplit((parsed.scheme, parsed.netloc, "/api/chat", "", ""))

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

    def _complete_openai(self, system_prompt: str, user_prompt: str) -> str:
        response = self._post(self.endpoint, self._openai_payload(system_prompt, user_prompt))
        response.raise_for_status()
        self.transport = "openai-compatible"
        self.active_endpoint = self.endpoint
        return self._parse_openai(response.json())

    def _complete_ollama(self, system_prompt: str, user_prompt: str) -> str:
        endpoint = self._ollama_native_endpoint(self.endpoint)
        response = self._post(endpoint, self._ollama_payload(system_prompt, user_prompt))
        response.raise_for_status()
        self.transport = "ollama-native"
        self.active_endpoint = endpoint
        return self._parse_ollama(response.json())

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        if not self.configured:
            raise RuntimeError("No model provider configured")

        # Reuse the known-good transport once discovered.
        if self.transport == "ollama-native":
            return self._complete_ollama(system_prompt, user_prompt)
        if self.transport == "openai-compatible":
            return self._complete_openai(system_prompt, user_prompt)

        # A configuration may explicitly point to /api/chat.
        if urlsplit(self.endpoint).path.rstrip("/") == "/api/chat":
            response = self._post(self.endpoint, self._ollama_payload(system_prompt, user_prompt))
            response.raise_for_status()
            self.transport = "ollama-native"
            self.active_endpoint = self.endpoint
            return self._parse_ollama(response.json())

        try:
            return self._complete_openai(system_prompt, user_prompt)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise
            # Ollama installations may expose only the native API. Retry on the
            # same origin; any failure here is surfaced to the normal copilot
            # deterministic fallback rather than hidden.
            return self._complete_ollama(system_prompt, user_prompt)


class CaseCopilot(CitationCaseCopilot):
    def __init__(self, case_dir, *, sigma_rules: str = "rules/sigma", provider: ModelProvider | None = None) -> None:
        super().__init__(case_dir, sigma_rules=sigma_rules, provider=provider or ModelProvider())

    def answer(self, question: str, *, max_sources: int = 12) -> dict[str, Any]:
        result = super().answer(question, max_sources=max_sources)
        result["transport"] = getattr(self.provider, "transport", None)
        result["active_endpoint"] = getattr(self.provider, "active_endpoint", None)
        return result


def install_base_patch() -> None:
    """Patch modules that imported the original copilot class before v3 loads."""
    import app.web.dashboard as dashboard

    dashboard.CaseCopilot = CaseCopilot


__all__ = ["CaseCopilot", "CopilotSource", "ModelProvider", "install_base_patch"]
