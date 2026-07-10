"""The flag subsystem: scanner -> decode ladder -> ranker + decoy filter ->
submit policy. See ARCHITECTURE.md §Flag Subsystem."""
from lotusmcp.flag.ladder import Decoded, decode_ladder
from lotusmcp.flag.scanner import FlagCandidate, scan_many, scan_text

__all__ = [
    "Decoded",
    "decode_ladder",
    "FlagCandidate",
    "scan_text",
    "scan_many",
]
