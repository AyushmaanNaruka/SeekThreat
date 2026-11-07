"""OllamaModelClient over httpx.MockTransport: request shape, think-tag stripping, errors."""

from __future__ import annotations

import json

import httpx
import pytest

from services.assistant.client import (
    FakeModelClient,
    ModelUnavailableError,
    OllamaModelClient,
    strip_think,
)
from services.assistant.interfaces import ModelClient
from services.assistant.prompts import REFUSAL_TEXT


def _client(handler: httpx.MockTransport) -> OllamaModelClient:
    return OllamaModelClient(
        "http://ollama.test:11434/", "qwen-test", "embed-test", timeout_s=5, transport=handler
    )


def test_both_clients_satisfy_the_protocol() -> None:
    assert isinstance(FakeModelClient(), ModelClient)
    assert isinstance(_client(httpx.MockTransport(lambda r: httpx.Response(200))), ModelClient)


def test_generate_sends_deterministic_chat_request_and_strips_think() -> None:
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/chat"
        seen.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={"message": {"role": "assistant", "content": "<think>hmm\nok</think>\nAnswer."}},
        )

    out = _client(httpx.MockTransport(handler)).generate(system="SYS", prompt="Q")
    assert out == "Answer."
    body = seen[0]
    assert body["model"] == "qwen-test"
    assert body["stream"] is False
    assert body["options"] == {"temperature": 0, "seed": 0}
    assert body["messages"] == [
        {"role": "system", "content": "SYS"},
        {"role": "user", "content": "Q"},
    ]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("<think>a</think>b<think>c</think>d", "bd"),
        ("reasoning without an opening tag</think>\nFinal.", "Final."),
        ("Final.<think>cut off mid-thought", "Final."),
        ("<THINK>x</THINK> y", "y"),
        ("plain", "plain"),
    ],
)
def test_strip_think(raw: str, expected: str) -> None:
    assert strip_think(raw) == expected


def test_embed_request_and_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/embed"
        body = json.loads(request.content)
        assert body == {"model": "embed-test", "input": ["a", "b"]}
        return httpx.Response(200, json={"embeddings": [[1, 0], [0, 1]]})

    client = _client(httpx.MockTransport(handler))
    assert client.embed(["a", "b"]) == [[1.0, 0.0], [0.0, 1.0]]
    assert client.embed([]) == []


def test_embed_count_mismatch_is_an_error() -> None:
    client = _client(
        httpx.MockTransport(lambda r: httpx.Response(200, json={"embeddings": [[1.0]]}))
    )
    with pytest.raises(ModelUnavailableError, match="1 vectors for 2 texts"):
        client.embed(["a", "b"])


def test_non_200_maps_to_model_unavailable() -> None:
    client = _client(
        httpx.MockTransport(lambda r: httpx.Response(404, json={"error": "model not found"}))
    )
    with pytest.raises(ModelUnavailableError, match="HTTP 404"):
        client.generate(system="s", prompt="p")


def test_connection_error_maps_to_model_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with pytest.raises(ModelUnavailableError, match="cannot reach Ollama"):
        _client(httpx.MockTransport(handler)).generate(system="s", prompt="p")


def test_timeout_maps_to_model_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(ModelUnavailableError, match="timed out"):
        _client(httpx.MockTransport(handler)).embed(["x"])


def test_malformed_body_maps_to_model_unavailable() -> None:
    client = _client(httpx.MockTransport(lambda r: httpx.Response(200, content=b"not json")))
    with pytest.raises(ModelUnavailableError, match="non-JSON"):
        client.generate(system="s", prompt="p")
    client = _client(httpx.MockTransport(lambda r: httpx.Response(200, json={"message": {}})))
    with pytest.raises(ModelUnavailableError, match="no message content"):
        client.generate(system="s", prompt="p")


def test_fake_generate_defaults() -> None:
    fake = FakeModelClient()
    assert fake.generate(system="s", prompt="no documents here") == REFUSAL_TEXT
    prompt = '<document n="1" id="finding:x" kind="finding">\nFirst line.\nSecond.\n</document>'
    assert fake.generate(system="s", prompt=prompt) == "First line. [cite:finding:x]"
    assert len(fake.generate_calls) == 2
