"""Cross-case Technique Library (Phase 7).

Allowlist-generalized playbook cards with Beta-posterior calibration and a
Thompson-sampled recommender; promotion is human-reviewed. A pure, rebuildable
fold of the library's own append-only log.
"""
from lotusmcp.library.technique import (
    TechniqueCard,
    TechniqueLibrary,
    technique_id,
)

__all__ = ["TechniqueLibrary", "TechniqueCard", "technique_id"]
