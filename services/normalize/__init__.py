"""Track 1 normalization: observations -> findings.

Only the interim bridge (D-044) exists so far. The full Track 1 normalizer (cross-scanner
dedup, asset joining) is owned by Utkarsh and will replace it.
"""

from services.normalize.interim_bridge import findings_from_observations

__all__ = ["findings_from_observations"]
