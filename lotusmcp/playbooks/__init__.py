"""Forward-chaining playbooks — the sole candidate generator (§4.4)."""
from lotusmcp.playbooks.engine import PlaybookEngine, Proposal, ProposalSet
from lotusmcp.playbooks.model import Entity, Finding, Hypothesis, Rule, World
from lotusmcp.playbooks.rules import ALL_RULES

__all__ = [
    "PlaybookEngine",
    "Proposal",
    "ProposalSet",
    "Entity",
    "Finding",
    "Hypothesis",
    "Rule",
    "World",
    "ALL_RULES",
]
