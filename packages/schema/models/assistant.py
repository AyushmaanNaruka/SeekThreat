"""Assistant inputs and outputs (Layer 4).

The assistant answers only from retrieved facts and must cite them. Every retrievable
unit is one fact with one citable id, so a citation always resolves to exactly one
record (DECISIONS.md D-048).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from packages.schema.models.citation import Citation, CitationKind

RetrievalMethod = Literal["vector", "lexical", "hybrid"]


class AssistantDocument(BaseModel):
    """One retrievable fact. `doc_id` is the id a citation uses, e.g. `obs:sha256:...`,
    `finding:fnd-...`, `path:...`, `chokepoint:fnd-...`, `topology:sha256:...`."""

    model_config = ConfigDict(frozen=True)

    doc_id: str
    kind: CitationKind
    engagement_id: str
    title: str
    # What is embedded and shown to the model. Built deterministically from the record.
    text: str
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("doc_id", "text")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("doc_id and text must be non-empty")
        return value


class RetrievedDocument(BaseModel):
    model_config = ConfigDict(frozen=True)

    document: AssistantDocument
    score: float
    method: RetrievalMethod


class CitationRepair(BaseModel):
    """A malformed citation id the model wrote that resolved to exactly one supplied
    document by a named deterministic rule (e.g. one character off, a stray `#Step 2`
    fragment). Kept so the analyst can see what the model actually wrote."""

    model_config = ConfigDict(frozen=True)

    cited: str
    resolved: str
    rule: str


class GroundingCheck(BaseModel):
    """Deterministic post-generation check: every CVE id, IP address and port the text
    mentions must appear in the documents it cites (or the question). Anything else is
    listed here and shown to the analyst."""

    model_config = ConfigDict(frozen=True)

    checked_entities: tuple[str, ...] = ()
    unsupported_entities: tuple[str, ...] = ()
    # Citation ids the model produced that were not among the supplied documents.
    invalid_citations: tuple[str, ...] = ()
    # Near-miss ids mapped to the one supplied document they unambiguously name.
    repaired_citations: tuple[CitationRepair, ...] = ()

    @property
    def grounded(self) -> bool:
        return not self.unsupported_entities and not self.invalid_citations


class Answer(BaseModel):
    """The assistant's reply to one question."""

    model_config = ConfigDict(frozen=True)

    question: str
    engagement_id: str
    text: str
    citations: tuple[Citation, ...] = ()
    # True when the assistant declined: nothing relevant retrieved, or the model said the
    # data does not support an answer. "I don't have that data" is a correct answer.
    refused: bool = False
    refusal_reason: str | None = None
    retrieved: tuple[RetrievedDocument, ...] = ()
    grounding: GroundingCheck = Field(default_factory=GroundingCheck)
    model: str


class PathNarration(BaseModel):
    """Plain-language narration of one proven attack path. Produced strictly downstream
    of the graph engine from the path's own edges and evidence (Hard Rule 1)."""

    model_config = ConfigDict(frozen=True)

    path_id: str
    engagement_id: str
    text: str
    citations: tuple[Citation, ...] = ()
    grounding: GroundingCheck = Field(default_factory=GroundingCheck)
    model: str
