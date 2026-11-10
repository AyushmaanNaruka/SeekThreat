"""Track 1 normalization: observations -> findings.

Only the interim bridge (D-044) and version matching (D-049, Proposed) exist so far.
The full Track 1 normalizer (cross-scanner dedup, asset joining) is owned by Utkarsh and
will replace it.
"""

from services.normalize.interim_bridge import findings_from_observations
from services.normalize.version_match import version_match_cve_ids, version_match_findings

__all__ = ["findings_from_observations", "version_match_cve_ids", "version_match_findings"]
