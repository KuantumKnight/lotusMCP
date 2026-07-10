"""OODA engine primitives. Phase 3 adds the full step() loop; the candidate
model + playbook prior (U(A)) land first."""
from lotusmcp.engine.candidate import PHASE_PAYOFF, PHASES, CandidateAction

__all__ = ["CandidateAction", "PHASES", "PHASE_PAYOFF"]
