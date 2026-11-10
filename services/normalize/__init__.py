"""Track 1 normalization: observations -> identity-resolved, de-duplicated findings.

`normalize_scan_observations` / `normalize_observations` (pipeline.py) are the entry
points; `identity.py` resolves assets and `dedup.py` merges findings (DECISIONS.md D-045,
proposed). `findings_from_observations` is the superseded D-044 interim bridge, still
exported for its own tests.
"""

from services.normalize.interim_bridge import findings_from_observations
from services.normalize.pipeline import (
    NormalizationResult,
    normalize_observations,
    normalize_scan_observations,
)

__all__ = [
    "NormalizationResult",
    "findings_from_observations",
    "normalize_observations",
    "normalize_scan_observations",
]
