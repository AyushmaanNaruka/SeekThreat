"""Citations for assistant answers.

Every answer points at the observations, findings or paths it drew on.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

CitationKind = Literal["observation", "finding", "path", "source"]


class Citation(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: CitationKind
    ref_id: str
    excerpt: str | None = None
