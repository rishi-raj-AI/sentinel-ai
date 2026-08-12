import httpx

from app.forensics.case_copilot_v3 import ModelProvider


class QueueProvider(ModelProvider):
    def __init__(self, endpoint="http://127.0.0.1:11434/v1/chat/completions"):
        self.endpoint = endpoint
        self.model = "llama3.2"
        self.api_key = ""
        self.timeout = 5.0
        self.config_source = "test"
        self.transport = None
        self.active_endpoint = None
        self.calls = []
        self.responses = []

    @property
    def configured(self):
        return True

    def _post(self, endpoint, payload):
        self.calls.append((endpoint, payload))
        return self.responses.pop(0)


def response(status, body, url):
    request = httpx.Request("POST", url)
    return httpx.Response(status, json=body, request=request)


def test_provider_falls_back_to_ollama_native_on_openai_404():
    provider = QueueProvider()
    provider.responses = [
        response(404, {"error": "not found"}, provider.endpoint),
        response(200, {"message": {"role": "assistant", "content": "Grounded [FLOW:2]."}}, "http://127.0.0.1:11434/api/chat"),
    ]

    result = provider.complete("system", "user")

    assert result == "Grounded [FLOW:2]."
    assert provider.transport == "ollama-native"
    assert provider.active_endpoint == "http://127.0.0.1:11434/api/chat"
    assert [call[0] for call in provider.calls] == [
        "http://127.0.0.1:11434/v1/chat/completions",
        "http://127.0.0.1:11434/api/chat",
    ]
    assert provider.calls[1][1]["stream"] is False


def test_provider_keeps_openai_transport_when_route_succeeds():
    provider = QueueProvider()
    provider.responses = [
        response(200, {"choices": [{"message": {"content": "Grounded [FLOW:2]."}}]}, provider.endpoint),
    ]

    result = provider.complete("system", "user")

    assert result == "Grounded [FLOW:2]."
    assert provider.transport == "openai-compatible"
    assert provider.active_endpoint == provider.endpoint
    assert len(provider.calls) == 1


def test_provider_accepts_explicit_ollama_native_endpoint():
    provider = QueueProvider("http://127.0.0.1:11434/api/chat")
    provider.responses = [
        response(200, {"message": {"content": "Native [EVIDENCE:E0003]."}}, provider.endpoint),
    ]

    result = provider.complete("system", "user")

    assert result == "Native [EVIDENCE:E0003]."
    assert provider.transport == "ollama-native"
    assert provider.active_endpoint == provider.endpoint
    assert len(provider.calls) == 1
