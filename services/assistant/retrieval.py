"""Hybrid retrieval: exact-term lexical match first, then vector similarity.

Questions about security data are dominated by exact identifiers (a CVE id, an IP, a
port). Embeddings blur those: CVE-2021-41773 and CVE-2021-42013 embed almost the same.
So every exact identifier in the question is matched lexically first, and vector search
fills the remaining slots for the free-text part of the question.

`InMemoryVectorStore` is the reference VectorStore used by tests and the CLI. The
pgvector store (DECISIONS.md D-005) lives in apps/api and must behave the same way.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Sequence
from functools import lru_cache

from packages.schema.models.assistant import AssistantDocument, RetrievedDocument
from services.assistant.interfaces import ModelClient, VectorStore

# ----------------------------------------------------------------------- term extraction

_CVE = re.compile(r"(?<![A-Za-z0-9])CVE-[0-9]{4}-[0-9]{4,7}(?![0-9])", re.IGNORECASE)
_CWE = re.compile(r"(?<![A-Za-z0-9])CWE-[0-9]{1,5}(?![0-9])", re.IGNORECASE)
_IPV4 = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9]|\.[0-9])")
_IPV6 = re.compile(r"(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
_PORT_PROTO = re.compile(r"(?<![A-Za-z0-9])([0-9]{1,5})/(tcp|udp|sctp)(?![A-Za-z0-9])", re.I)
_BARE_PORT = re.compile(r"\bports?\s*:?\s*([0-9]{1,5})(?![0-9]|/(?:tcp|udp|sctp)\b)", re.I)
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?"
_HOSTNAME = re.compile(rf"(?<![\w.-]){_LABEL}(?:\.{_LABEL})+(?![\w-]|\.[A-Za-z0-9])")
# Dotted tokens that are file names or code, not hosts.
_NOT_HOST_SUFFIXES = frozenset(
    [
        "asp",
        "aspx",
        "cgi",
        "conf",
        "css",
        "htm",
        "html",
        "ini",
        "java",
        "jpg",
        "js",
        "json",
        "jsp",
        "log",
        "md",
        "php",
        "png",
        "py",
        "sh",
        "txt",
        "xml",
        "yaml",
        "yml",
    ]
)


def _valid_port(text: str) -> bool:
    return 0 < int(text) < 65536


def _hostname(token: str) -> str | None:
    last = token.rsplit(".", 1)[-1]
    if len(last) < 2 or not any(c.isalpha() for c in last) or last.isdigit():
        return None
    if last.lower() in _NOT_HOST_SUFFIXES:
        return None
    return token.lower()


def extract_terms(text: str) -> list[str]:
    """Exact identifiers in `text`, in order of first appearance, de-duplicated.

    CVE and CWE ids (upper case), IPv4/IPv6 addresses (canonical form), `port/proto`
    (`8080/tcp`), bare ports after the word "port" (`22`), and host-name-like dotted
    tokens (lower case). Deterministic: pure regex, no model.
    """
    found: list[tuple[int, str]] = []
    for m in _CVE.finditer(text):
        found.append((m.start(), m.group(0).upper()))
    for m in _CWE.finditer(text):
        found.append((m.start(), m.group(0).upper()))
    ipv4_spans: list[tuple[int, int]] = []
    for m in _IPV4.finditer(text):
        try:
            found.append((m.start(), str(ipaddress.IPv4Address(m.group(0)))))
            ipv4_spans.append(m.span())
        except ValueError:
            continue
    for m in _IPV6.finditer(text):
        token = m.group(0)
        if not any(c not in ":" for c in token):
            continue
        try:
            found.append((m.start(), ipaddress.IPv6Address(token).compressed))
        except ValueError:
            continue
    for m in _PORT_PROTO.finditer(text):
        if _valid_port(m.group(1)):
            found.append((m.start(), f"{int(m.group(1))}/{m.group(2).lower()}"))
    for m in _BARE_PORT.finditer(text):
        if _valid_port(m.group(1)):
            found.append((m.start(1), str(int(m.group(1)))))
    for m in _HOSTNAME.finditer(text):
        if any(s <= m.start() < e for s, e in ipv4_spans):
            continue
        host = _hostname(m.group(0))
        if host is not None:
            found.append((m.start(), host))
    seen: set[str] = set()
    terms: list[str] = []
    for _, term in sorted(found, key=lambda item: (item[0], item[1])):
        if term not in seen:
            seen.add(term)
            terms.append(term)
    return terms


@lru_cache(maxsize=4096)
def _term_pattern(term: str) -> re.Pattern[str]:
    escaped = re.escape(term)
    if term.isdigit():
        # A bare port: "22" must match "...:22/tcp" or "port 22", never "172.20.1.22".
        return re.compile(rf"(?<![A-Za-z0-9.]){escaped}(?![A-Za-z0-9]|\.[0-9])")
    if ":" in term:
        return re.compile(rf"(?<![0-9A-Fa-f:]){escaped}(?![0-9A-Fa-f:])", re.IGNORECASE)
    return re.compile(rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9]|\.[0-9])", re.IGNORECASE)


def contains_term(text: str, term: str) -> bool:
    """True when `term` occurs in `text` as a whole identifier, case-insensitively.

    `172.20.1.1` does not match inside `172.20.1.13`, and `CVE-2021-4177` does not match
    inside `CVE-2021-41773`.
    """
    return _term_pattern(term).search(text) is not None


# ------------------------------------------------------------------------- vector store


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    if len(a) != len(b):
        raise ValueError(f"vector dimensions differ: {len(a)} vs {len(b)}")
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


class InMemoryVectorStore:
    """Engagement-scoped, in-process VectorStore. Ties break by doc_id, so results are
    deterministic."""

    def __init__(self) -> None:
        self._docs: dict[str, dict[str, tuple[AssistantDocument, tuple[float, ...]]]] = {}

    def upsert(
        self, documents: Sequence[AssistantDocument], vectors: Sequence[Sequence[float]]
    ) -> None:
        if len(documents) != len(vectors):
            raise ValueError(f"{len(documents)} documents but {len(vectors)} vectors")
        for doc, vector in zip(documents, vectors, strict=True):
            self._docs.setdefault(doc.engagement_id, {})[doc.doc_id] = (
                doc,
                tuple(float(x) for x in vector),
            )

    def search(
        self, *, engagement_id: str, vector: Sequence[float], limit: int
    ) -> list[RetrievedDocument]:
        if limit <= 0:
            return []
        scored = [
            (_cosine(vector, vec), doc) for doc, vec in self._docs.get(engagement_id, {}).values()
        ]
        scored.sort(key=lambda item: (-item[0], item[1].doc_id))
        return [
            RetrievedDocument(document=doc, score=score, method="vector")
            for score, doc in scored[:limit]
        ]

    def lexical(
        self, *, engagement_id: str, terms: Sequence[str], limit: int
    ) -> list[RetrievedDocument]:
        unique = list(dict.fromkeys(terms))
        if limit <= 0 or not unique:
            return []
        hits: list[tuple[int, AssistantDocument]] = []
        for doc, _ in self._docs.get(engagement_id, {}).values():
            matched = sum(1 for term in unique if contains_term(doc.text, term))
            if matched:
                hits.append((matched, doc))
        hits.sort(key=lambda item: (-item[0], item[1].doc_id))
        return [
            RetrievedDocument(document=doc, score=float(matched), method="lexical")
            for matched, doc in hits[:limit]
        ]

    def get(self, *, engagement_id: str, doc_id: str) -> AssistantDocument | None:
        entry = self._docs.get(engagement_id, {}).get(doc_id)
        return entry[0] if entry else None

    def delete_engagement(self, engagement_id: str) -> None:
        self._docs.pop(engagement_id, None)


# ---------------------------------------------------------------------------- retriever


class Retriever:
    """Indexes documents and answers hybrid queries against a VectorStore."""

    batch_size = 32

    def __init__(self, store: VectorStore, client: ModelClient) -> None:
        self._store = store
        self._client = client

    @property
    def store(self) -> VectorStore:
        return self._store

    def index(self, documents: Sequence[AssistantDocument]) -> int:
        """Embed and upsert `documents`. Returns how many were indexed."""
        count = 0
        for start in range(0, len(documents), self.batch_size):
            batch = list(documents[start : start + self.batch_size])
            vectors = self._client.embed([doc.text for doc in batch])
            if len(vectors) != len(batch):
                raise ValueError(f"embedder returned {len(vectors)} vectors for {len(batch)}")
            self._store.upsert(batch, vectors)
            count += len(batch)
        return count

    def retrieve(
        self,
        *,
        engagement_id: str,
        question: str,
        limit: int = 8,
        min_vector_score: float = 0.2,
    ) -> list[RetrievedDocument]:
        """Lexical exact-term hits first (method "lexical", or "hybrid" when vector search
        also found them), then vector hits scoring at least `min_vector_score`.

        Lexical scores are the fraction of the question's terms a document contains;
        vector scores are cosine similarity. De-duplicated, deterministic, at most `limit`.
        """
        if limit <= 0 or not question.strip():
            return []
        terms = extract_terms(question)
        lexical = (
            self._store.lexical(engagement_id=engagement_id, terms=terms, limit=limit)
            if terms
            else []
        )
        [query_vector] = self._client.embed([question])
        vector_hits = [
            hit
            for hit in self._store.search(
                engagement_id=engagement_id, vector=query_vector, limit=limit
            )
            if hit.score >= min_vector_score
        ]
        vector_ids = {hit.document.doc_id for hit in vector_hits}

        out: list[RetrievedDocument] = []
        seen: set[str] = set()
        for hit in lexical:
            doc_id = hit.document.doc_id
            if doc_id in seen:
                continue
            seen.add(doc_id)
            out.append(
                RetrievedDocument(
                    document=hit.document,
                    score=hit.score / len(terms),
                    method="hybrid" if doc_id in vector_ids else "lexical",
                )
            )
        for hit in vector_hits:
            if hit.document.doc_id in seen:
                continue
            seen.add(hit.document.doc_id)
            out.append(hit)
        return out[:limit]
