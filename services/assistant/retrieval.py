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

from packages.schema.models.assistant import AssistantDocument, RetrievalMethod, RetrievedDocument
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


# ------------------------------------------------------------------ question analysis

# Citable ids an analyst may paste into a question: path:..., finding:fnd-..., etc.
_DOC_ID = re.compile(
    r"(?<![\w:])(?:obs|finding|path|chokepoint|topology):"
    r"[A-Za-z0-9](?:[A-Za-z0-9:._-]*[A-Za-z0-9])?"
)
# Host names without a dot (dmz-proxy, jenkins-ci): dash-joined, starting with a letter.
_DASHED_NAME = re.compile(r"(?<![\w.:/-])[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+(?![\w/-]|\.\w|:\S)")
_NOT_NAME_PREFIXES = ("cve-", "cwe-", "fnd-")
_ENDPOINT = re.compile(r"(?<![0-9.])((?:[0-9]{1,3}\.){3}[0-9]{1,3}):([0-9]{1,5})/(tcp|udp|sctp)\b")
_EVIDENCE_LINE = re.compile(r"^\s*(Evidence|Findings): (.+)$", re.MULTILINE)
_OBSERVATIONS_LINE = re.compile(r"^Observations: (.+)$", re.MULTILINE)

# Question intent, by keyword. It only decides which document kinds rank first; it never
# adds a fact that the exact-term match did not find.
_PATH_INTENT = re.compile(
    r"\b(?:attack[- ]?)?paths?\b|\bchain|\bwalk (?:me )?through\b|\breach|\benter", re.I
)
_FIX_INTENT = re.compile(r"\bchokepoints?\b|\bfix|\bremediat|\bpatch|\bbreak", re.I)
_SERVICE_INTENT = re.compile(r"\bproduct|\bversion|\bservice|\bsoftware|\brunning|\bports?\b", re.I)


def extract_doc_ids(text: str) -> list[str]:
    """Citable document ids named in `text` (`path:...`, `finding:fnd-...`), in order,
    de-duplicated."""
    return list(dict.fromkeys(m.group(0) for m in _DOC_ID.finditer(text)))


def extract_host_names(text: str) -> list[str]:
    """Dash-joined host names (`dmz-proxy`) that `extract_terms` misses because they have
    no dot. Lower case, in order, de-duplicated; CVE/CWE/finding ids and citable ids are
    excluded."""
    masked = _DOC_ID.sub(" ", text)
    names = [
        m.group(0).lower()
        for m in _DASHED_NAME.finditer(masked)
        if not m.group(0).lower().startswith(_NOT_NAME_PREFIXES)
    ]
    return list(dict.fromkeys(names))


def host_aliases(name: str, documents: Sequence[AssistantDocument]) -> list[str]:
    """IPv4 addresses the documents themselves tie to host `name`, in order.

    Only explicit forms count: a label `name (ip, ip)` or `Multi-homed host name: ip, ip`
    (path and topology documents), and an observation whose `hostname`/`hostnames`
    attribute contains `name`, which ties it to the address in the observation's subject.
    """
    label = re.compile(
        rf"(?<![A-Za-z0-9-]){re.escape(name)}(?:\s*\(|:\s+)((?:[0-9.]+(?:,\s*)?)+)", re.I
    )
    found: list[str] = []
    for doc in documents:
        for m in label.finditer(doc.text):
            found += [t for t in extract_terms(m.group(1)) if "." in t]
        if doc.kind == "observation":
            lines = doc.text.splitlines()
            if any(
                ln.startswith(("hostname:", "hostnames:")) and contains_term(ln, name)
                for ln in lines
            ):
                found += [str(ipaddress.IPv4Address(m.group(0))) for m in _IPV4.finditer(lines[0])]
    return list(dict.fromkeys(found))


def _doc_class(doc: AssistantDocument) -> str:
    return "chokepoint" if doc.doc_id.startswith("chokepoint:") else doc.kind


def _kind_rank(doc: AssistantDocument, *, path_intent: bool, fix_intent: bool) -> int:
    """0 ranks first. Path documents mention every entity on the path, so on term overlap
    alone they would top almost every query; they lead only for path questions."""
    cls = _doc_class(doc)
    if fix_intent:
        if cls == "chokepoint":
            return 0
        return 2 if cls == "path" and not path_intent else 1
    if path_intent:
        return 0 if cls == "path" else 1
    return 1 if cls == "path" else 0


_ORDINALS = {"first": 1, "top": 1, "second": 2, "third": 3, "fourth": 4, "fifth": 5}
_RANK_NUMBER = r"(\d{1,3}|first|top|second|third|fourth|fifth)"
_CHOKEPOINT_RANK = re.compile(
    rf"\brank(?:ed)?\s*(?:#|no\.?\s*)?{_RANK_NUMBER}\s+chokepoint\b"
    rf"|\bchokepoint\s+(?:ranked|at rank|rank)\s*{_RANK_NUMBER}\b",
    re.I,
)
_PATH_RANK = re.compile(
    rf"\brank(?:ed)?\s*(?:#|no\.?\s*)?{_RANK_NUMBER}\s+(?:attack\s+)?path\b"
    rf"|\bpath\s+(?:is\s+)?(?:ranked|at rank|rank)\s*{_RANK_NUMBER}\b",
    re.I,
)
_ALL_CHOKEPOINTS = re.compile(r"\bchokepoints\b", re.I)
_WORD = re.compile(r"[a-z][a-z0-9]{3,}")
_STOPWORDS = frozenset(
    [
        "what",
        "which",
        "where",
        "when",
        "does",
        "with",
        "this",
        "that",
        "from",
        "into",
        "have",
        "there",
        "their",
        "about",
        "would",
        "could",
        "should",
        "engagement",
        "according",
    ]
)


def _rank_value(token: str) -> int:
    return int(token) if token.isdigit() else _ORDINALS[token.lower()]


def rank_terms(question: str) -> list[str]:
    """Exact phrases for rank references: "the rank 2 chokepoint" -> `Chokepoint rank 2:`
    and "the path ranked first" -> `Rank: 1.`, as the chokepoint and path documents
    render them. "the chokepoints" with no rank -> `Chokepoint rank` (all of them)."""
    terms: list[str] = []
    for m in _CHOKEPOINT_RANK.finditer(question):
        terms.append(f"Chokepoint rank {_rank_value(m.group(1) or m.group(2))}:")
    for m in _PATH_RANK.finditer(question):
        terms.append(f"Rank: {_rank_value(m.group(1) or m.group(2))}.")
    if not terms and _ALL_CHOKEPOINTS.search(question):
        terms.append("Chokepoint rank")
    return list(dict.fromkeys(terms))


def _record_rank(doc: AssistantDocument, *, path_intent: bool, fix_intent: bool) -> int:
    """The engine's own rank (lower is better) for the kind the question asks about:
    paths for path questions, chokepoints for fix questions. Other documents tie."""
    cls = _doc_class(doc)
    wanted = (cls == "path" and path_intent) or (cls == "chokepoint" and fix_intent)
    rank = doc.metadata.get("rank", "")
    return int(rank) if wanted and rank.isdigit() else 1_000_000


def _word_overlap(question_words: frozenset[str], doc: AssistantDocument) -> int:
    return len(question_words & set(_WORD.findall(doc.text.lower())))


def evidence_ids(doc: AssistantDocument) -> list[str]:
    """Evidence and finding ids a path document lists for its steps, in order."""
    ids: list[str] = []
    for m in _EVIDENCE_LINE.finditer(doc.text):
        for part in m.group(2).split(","):
            ref = part.strip()
            if ref:
                ids.append(ref if m.group(1) == "Evidence" else f"finding:{ref}")
    return list(dict.fromkeys(ids))


# ---------------------------------------------------------------------------- retriever


class Retriever:
    """Indexes documents and answers hybrid queries against a VectorStore."""

    batch_size = 32
    # Candidate pool fetched from the store before re-ranking.
    lexical_pool = 64

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

    def term_groups(self, *, engagement_id: str, question: str) -> list[tuple[str, ...]]:
        """One group per exact identifier in the question. A host name's group also holds
        the addresses the engagement's own documents tie to it (`host_aliases`), so a
        document naming either form matches that group."""
        groups: list[tuple[str, ...]] = [(term,) for term in extract_terms(question)]
        # Dotted host names from extract_terms (lower case; CVE/CWE ids are upper case).
        dotted = [
            g[0]
            for g in groups
            if "." in g[0] and g[0].islower() and not any(c in g[0] for c in ":/")
        ]
        for name in dotted:
            holders = self._store.lexical(
                engagement_id=engagement_id, terms=[name], limit=self.lexical_pool
            )
            aliases = host_aliases(name, [hit.document for hit in holders])
            groups[groups.index((name,))] = tuple(dict.fromkeys([name, *aliases]))
        for name in extract_host_names(question):
            if (name,) in groups:
                continue
            holders = self._store.lexical(
                engagement_id=engagement_id, terms=[name], limit=self.lexical_pool
            )
            # A dash-joined word no document contains ("best-ranked") is not a host name.
            if holders:
                aliases = host_aliases(name, [hit.document for hit in holders])
                groups.append(tuple(dict.fromkeys([name, *aliases])))
        groups += [(term,) for term in rank_terms(question)]
        return groups

    def retrieve(
        self,
        *,
        engagement_id: str,
        question: str,
        limit: int = 8,
        min_vector_score: float = 0.2,
        focused_limit: int = 4,
    ) -> list[RetrievedDocument]:
        """Named documents first, then exact-term hits, then vector hits only when no
        document holds every identifier in the question.

        1. Documents the question names by id (`path:...`) are fetched directly and come
           first (method "lexical", score 1.0). If the question names ids and holds no
           other identifier, only those documents are returned.
        2. Exact identifiers (`term_groups`) are matched lexically. Hits rank by document
           kind for the question's intent (path documents lead only for path questions,
           chokepoints for fix questions), then by the share of the question's
           identifier groups they hold (their score), then by path rank, then by id.
        3. If some hit holds every group, the context is focused: at most `focused_limit`
           lexical hits besides the named documents, and no vector fill. Otherwise
           vector hits scoring at least `min_vector_score` fill the remaining slots.
        4. For product/version/service/port questions, one exact hop: observations of an
           `ip:port/proto` endpoint the hits name or, for path questions, the
           observations and findings the best path cites as evidence.

        Deterministic, de-duplicated, engagement-scoped, at most `limit`.
        """
        if limit <= 0 or not question.strip():
            return []
        out: list[RetrievedDocument] = []
        seen: set[str] = set()

        def add(doc: AssistantDocument, score: float, method: RetrievalMethod) -> None:
            if doc.doc_id not in seen and doc.engagement_id == engagement_id:
                seen.add(doc.doc_id)
                out.append(RetrievedDocument(document=doc, score=score, method=method))

        for doc_id in extract_doc_ids(question):
            named = self._store.get(engagement_id=engagement_id, doc_id=doc_id)
            if named is not None:
                add(named, 1.0, "lexical")
        pinned = len(out)

        groups = self.term_groups(engagement_id=engagement_id, question=question)
        if pinned and not groups:
            return out[:limit]

        path_intent = bool(_PATH_INTENT.search(question))
        fix_intent = bool(_FIX_INTENT.search(question))
        words = frozenset(w for w in _WORD.findall(question.lower()) if w not in _STOPWORDS)
        ranked: list[tuple[tuple[int, float, int, int, str], AssistantDocument, float]] = []
        if groups:
            terms = list(dict.fromkeys(t for g in groups for t in g))
            for hit in self._store.lexical(
                engagement_id=engagement_id, terms=terms, limit=self.lexical_pool
            ):
                doc = hit.document
                covered = sum(1 for g in groups if any(contains_term(doc.text, t) for t in g))
                if not covered:
                    continue
                coverage = covered / len(groups)
                key = (
                    _kind_rank(doc, path_intent=path_intent, fix_intent=fix_intent),
                    -coverage,
                    _record_rank(doc, path_intent=path_intent, fix_intent=fix_intent),
                    -_word_overlap(words, doc),
                    doc.doc_id,
                )
                ranked.append((key, doc, coverage))
            ranked.sort(key=lambda item: item[0])
        focused = any(coverage == 1.0 for _, _, coverage in ranked)

        [query_vector] = self._client.embed([question])
        vector_hits = [
            hit
            for hit in self._store.search(
                engagement_id=engagement_id, vector=query_vector, limit=limit
            )
            if hit.score >= min_vector_score
        ]
        vector_ids = {hit.document.doc_id for hit in vector_hits}

        lexical_cap = min(pinned + focused_limit, limit) if focused else limit
        for _, doc, coverage in ranked:
            if len(out) >= lexical_cap:
                break
            add(doc, coverage, "hybrid" if doc.doc_id in vector_ids else "lexical")

        if _SERVICE_INTENT.search(question):
            for doc in self._service_context(engagement_id, out, path_intent=path_intent):
                add(doc, 0.0, "lexical")

        if not focused:
            for hit in vector_hits:
                add(hit.document, hit.score, hit.method)
        return out[:limit]

    def _service_context(
        self, engagement_id: str, current: Sequence[RetrievedDocument], *, path_intent: bool
    ) -> list[AssistantDocument]:
        """One exact hop from the current hits (see `retrieve`, step 4)."""
        docs = [hit.document for hit in current]
        top_path = next((d for d in docs if d.kind == "path"), None)
        if path_intent and top_path is not None:
            found: list[AssistantDocument] = []
            for ref in evidence_ids(top_path):
                doc = self._store.get(engagement_id=engagement_id, doc_id=ref)
                if doc is not None and doc.kind in ("observation", "finding"):
                    found.append(doc)
            return found
        # A chokepoint names its finding; the finding names its observations, which carry
        # the endpoint. Follow those stored links, never a guess.
        linked: list[AssistantDocument] = []
        for doc in docs:
            if _doc_class(doc) != "chokepoint":
                continue
            finding = self._store.get(
                engagement_id=engagement_id, doc_id="finding:" + doc.doc_id.split(":", 1)[1]
            )
            if finding is None:
                continue
            linked.append(finding)
            for m in _OBSERVATIONS_LINE.finditer(finding.text):
                for ref in m.group(1).rstrip(".").split(","):
                    obs = self._store.get(engagement_id=engagement_id, doc_id=ref.strip())
                    if obs is not None:
                        linked.append(obs)
        endpoints = list(
            dict.fromkeys(
                f"{ip}:{int(port)}/{proto.lower()}"
                for doc in [*docs, *linked]
                if doc.kind in ("observation", "finding")
                for ip, port, proto in _ENDPOINT.findall(doc.text)
            )
        )
        if not endpoints:
            return linked
        hits = self._store.lexical(
            engagement_id=engagement_id, terms=endpoints, limit=self.lexical_pool
        )
        same_endpoint = sorted(
            (
                hit.document
                for hit in hits
                if hit.document.kind == "observation"
                and any(contains_term(hit.document.text, e) for e in endpoints)
            ),
            key=lambda d: d.doc_id,
        )
        return [*linked, *same_endpoint]
