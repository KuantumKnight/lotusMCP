"""The flag subsystem: scanner -> decode ladder -> ranker + decoy filter ->
submit policy. See ARCHITECTURE.md §Flag Subsystem."""
from lotusmcp.flag.ladder import Decoded, decode_ladder
from lotusmcp.flag.policy import (
    BLOCKED,
    DONE,
    SUBMIT,
    WAIT,
    SubmitDecision,
    SubmitPolicy,
)
from lotusmcp.flag.ranker import RankedFlag, is_decoy, rank
from lotusmcp.flag.scanner import FlagCandidate, scan_many, scan_text

__all__ = [
    "Decoded",
    "decode_ladder",
    "FlagCandidate",
    "scan_text",
    "scan_many",
    "RankedFlag",
    "rank",
    "is_decoy",
    "SubmitPolicy",
    "SubmitDecision",
    "SUBMIT",
    "WAIT",
    "BLOCKED",
    "DONE",
]
