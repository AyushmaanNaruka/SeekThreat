"""ModelClient implementations (DECISIONS.md D-006).

- `OllamaModelClient` talks to an Ollama server over HTTP. Temperature 0 and a fixed seed,
  so the same prompt gives the same text where the backend honours it.
- `FakeModelClient` is deterministic and offline. For tests and CI only.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Callable, Sequence
from typing import Any

import httpx

from services.assistant.prompts import REFUSAL_TEXT, first_rendered_document

_THINK_BLOCK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_THINK_CLOSE = re.compile(r"</think>", re.IGNORECASE)
_THINK_OPEN = re.compile(r"<think>", re.IGNORECASE)


class ModelUnavailableError(RuntimeError):
    """The model server could not be reached or returned something unusable."""


def strip_think(text: str) -> str:
    """Remove reasoning-model `<think>...</think>` blocks and return the answer only.

    Handles the two malformed shapes reasoning models emit: a closing tag without an
    opening one (the template opened it), and an opening tag that never closes (the
    output was cut off mid-thought, so there is no answer to keep).
    """
    text = _THINK_BLOCK.sub("", text)
    closes = list(_THINK_CLOSE.finditer(text))
    if closes:
        text = text[closes[-1].end() :]
    opened = _THINK_OPEN.search(text)
    if opened:
        text = text[: opened.start()]
    return text.strip()


class OllamaModelClient:
    """ModelClient over the Ollama HTTP API (`/api/chat`, `/api/embed`).

    `transport` exists so tests can inject `httpx.MockTransport`; production leaves it None.
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        embed_model: str,
        timeout_s: float = 120.0,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._embed_model = embed_model
        self._timeout_s = timeout_s
        self._transport = transport

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def embed_model_name(self) -> str:
        return self._embed_model

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self._base_url}{path}"
        try:
            with httpx.Client(timeout=self._timeout_s, transport=self._transport) as http:
                response = http.post(url, json=payload)
        except httpx.TimeoutException as exc:
            raise ModelUnavailableError(
                f"Ollama at {self._base_url} timed out after {self._timeout_s}s on {path}"
            ) from exc
        except httpx.HTTPError as exc:
            raise ModelUnavailableError(
                f"cannot reach Ollama at {self._base_url} ({path}): {exc}"
            ) from exc
        if response.status_code != 200:
            body = response.text[:300]
            raise ModelUnavailableError(
                f"Ollama {path} returned HTTP {response.status_code}: {body}"
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise ModelUnavailableError(f"Ollama {path} returned a non-JSON body") from exc
        if not isinstance(data, dict):
            raise ModelUnavailableError(f"Ollama {path} returned an unexpected JSON shape")
        if "error" in data:
            raise ModelUnavailableError(f"Ollama {path} reported an error: {data['error']}")
        return data

    def generate(self, *, system: str, prompt: str) -> str:
        data = self._post(
            "/api/chat",
            {
                "model": self._model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
                "options": {"temperature": 0, "seed": 0},
            },
        )
        message = data.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise ModelUnavailableError("Ollama /api/chat response has no message content")
        return strip_think(content)

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []
        data = self._post("/api/embed", {"model": self._embed_model, "input": list(texts)})
        vectors = data.get("embeddings")
        if not isinstance(vectors, list) or len(vectors) != len(texts):
            raise ModelUnavailableError(
                f"Ollama /api/embed returned {len(vectors) if isinstance(vectors, list) else 0} "
                f"vectors for {len(texts)} texts"
            )
        try:
            return [[float(x) for x in vector] for vector in vectors]
        except (TypeError, ValueError) as exc:
            raise ModelUnavailableError("Ollama /api/embed returned a non-numeric vector") from exc


# ---------------------------------------------------------------------------- fake

_WORD = re.compile(r"[a-z0-9]+(?:[.:/-][a-z0-9]+)*")
_STOPWORDS = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "did",
        "do",
        "does",
        "for",
        "from",
        "has",
        "have",
        "how",
        "i",
        "in",
        "is",
        "it",
        "its",
        "me",
        "my",
        "of",
        "on",
        "or",
        "our",
        "that",
        "the",
        "their",
        "there",
        "this",
        "to",
        "was",
        "we",
        "were",
        "what",
        "when",
        "where",
        "which",
        "who",
        "why",
        "will",
        "with",
        "you",
        "your",
    ]
)


def _tokens(text: str) -> list[str]:
    out: list[str] = []
    for token in _WORD.findall(text.lower()):
        if token in _STOPWORDS:
            continue
        out.append(token)
        # Also index the parts of compound tokens ("172.20.1.13:8080/tcp" -> "8080").
        parts = re.split(r"[.:/-]", token)
        if len(parts) > 1:
            out.extend(p for p in parts if p and p not in _STOPWORDS)
    return out


class FakeModelClient:
    """Deterministic, offline ModelClient. For tests and CI only.

    - `embed`: hashed bag-of-words (sha256 bucket and sign), L2-normalised. Stable across
      runs and machines; no randomness.
    - `generate`: `responses(system, prompt)` if given; otherwise echoes the first line of
      the first framed document in the prompt with its citation, or the refusal sentence
      when the prompt carries no documents.

    Every call is recorded in `generate_calls` / `embed_calls` so tests can assert the
    model was (or was not) consulted.
    """

    def __init__(self, responses: Callable[[str, str], str] | None = None, dim: int = 64) -> None:
        if dim < 1:
            raise ValueError("dim must be positive")
        self._responses = responses
        self._dim = dim
        self.generate_calls: list[tuple[str, str]] = []
        self.embed_calls: list[list[str]] = []

    @property
    def model_name(self) -> str:
        return "fake-model"

    @property
    def embed_model_name(self) -> str:
        return f"fake-embed-{self._dim}"

    def generate(self, *, system: str, prompt: str) -> str:
        self.generate_calls.append((system, prompt))
        if self._responses is not None:
            return self._responses(system, prompt)
        first = first_rendered_document(prompt)
        if first is None:
            return REFUSAL_TEXT
        doc_id, text = first
        line = next((ln.strip() for ln in text.splitlines() if ln.strip()), text.strip())
        return f"{line} [cite:{doc_id}]"

    def _vector(self, text: str) -> list[float]:
        vector = [0.0] * self._dim
        for token in _tokens(text):
            digest = hashlib.sha256(token.encode()).digest()
            bucket = int.from_bytes(digest[:4], "big") % self._dim
            vector[bucket] += 1.0 if digest[4] & 1 else -1.0
        norm = math.sqrt(sum(x * x for x in vector))
        return [x / norm for x in vector] if norm else vector

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        self.embed_calls.append(list(texts))
        return [self._vector(t) for t in texts]
