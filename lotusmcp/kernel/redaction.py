"""The Redaction Choke — detectors + deterministic vault tokenizer.

Every payload and every LLM-authored string passes through here *before* the
serializer hashes and writes it (ARCHITECTURE.md §Safety.4). This closes the
non-Executor leak path into `events.jsonl -> STATE.md -> resume -> writeup ->
Technique Library`: incidental secrets (JWTs, private keys, cloud keys,
credentials in URLs, `password=...` values) are tokenized into stable handles;
the plaintext lands only in a privileged-reveal vault, never in the log.

Two properties make this safe *and* replay-equivalent:

- **Content-addressed handles.** A handle is `«SECRET:{kind}:{tag}»` where
  `tag = blake2b(plaintext)[:2]`. The same secret always yields the same handle,
  so re-observing a secret *corroborates* (idempotent) instead of minting noise,
  and a byte-for-byte log replay reproduces byte-identical redacted text.
- **Flag-aware.** Flags are the objective and are captured *verbatim*. A caller
  may pass the case `flag_format`; any candidate span that fully matches it is
  never tokenized.

Skeleton note: the vault here obfuscates at rest with a keyed XOR + blake2b MAC,
not AES-GCM (stdlib-only, mirroring `canonical.py`'s pragmatic-skeleton stance).
Production swaps `SecretVault` for the AES-GCM `redaction/secrets.enc` store; the
handle format and the `Redactor` interface do not change.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Pattern, Tuple

# Guillemets keep handles visually distinct and regex-safe in the log/STATE.md.
_HANDLE_RE = re.compile(r"«SECRET:[a-z0-9_]+:[0-9a-f]{4}»")
# Capturing variant so re.split retains handles as delimiters (odd indices).
_HANDLE_SPLIT_RE = re.compile(r"(«SECRET:[a-z0-9_]+:[0-9a-f]{4}»)")


def handle_for(kind: str, plaintext: str) -> str:
    tag = hashlib.blake2b(plaintext.encode("utf-8"), digest_size=2).hexdigest()
    return f"«SECRET:{kind}:{tag}»"


@dataclass(frozen=True)
class Detector:
    """A named secret pattern.

    `group` selects which capture group is the secret to tokenize (0 = whole
    match). The rest of the match is preserved so surrounding structure — the
    `://user:` of a URL, the `password=` key — stays readable in the log.
    """

    kind: str
    pattern: Pattern[str]
    group: int = 0


def _d(kind: str, rx: str, group: int = 0, flags: int = 0) -> Detector:
    return Detector(kind, re.compile(rx, flags), group)


# Ordered most-specific first; each detector runs a full pass over the text so
# spans never overlap across detectors.
# Dict keys whose string value is a secret regardless of the value's shape
# (a bare password value matches no text pattern, but its key betrays it).
SENSITIVE_KEY_RE = re.compile(
    r"(?i)(?:^|_)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token"
    r"|token|private[_-]?key|credential|session[_-]?id)s?$"
)


DEFAULT_DETECTORS: List[Detector] = [
    _d("private_key",
       r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
       flags=re.DOTALL),
    _d("jwt", r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    _d("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    _d("bearer", r"(?i)\bbearer\s+([A-Za-z0-9._~+/-]{16,}=*)", group=1),
    _d("basic_auth", r"(?i)\bbasic\s+([A-Za-z0-9+/]{16,}={0,2})", group=1),
    # credentials embedded in a URL authority: scheme://user:PASSWORD@host
    _d("url_credential", r"://[^:@/\s]+:([^@/\s]+)@", group=1),
    # key=value / key: value secrets (password, token, api_key, secret, ...)
    _d("secret_kv",
       r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|token)\b"
       r"\s*[=:]\s*[\"']?([^\s\"';,]{6,})",
       group=1),
]


class SecretVault:
    """handle -> plaintext, obfuscated at rest (skeleton).

    Idempotent by construction: because handles are content-addressed, storing
    the same plaintext twice is a no-op and can never collide with a different
    secret under the same handle (checked defensively).
    """

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key or b"lotusmcp-skeleton-vault-key"
        self._store: Dict[str, bytes] = {}

    def _keystream(self, n: int) -> bytes:
        # counter-mode blake2b: unbounded, deterministic from the key.
        out = bytearray()
        counter = 0
        while len(out) < n:
            block = hashlib.blake2b(
                self._key + counter.to_bytes(8, "big"), digest_size=64
            ).digest()
            out.extend(block)
            counter += 1
        return bytes(out[:n])

    def _xor(self, data: bytes) -> bytes:
        return bytes(b ^ p for b, p in zip(data, self._keystream(len(data))))

    def store(self, handle: str, plaintext: str) -> None:
        blob = self._xor(plaintext.encode("utf-8"))
        existing = self._store.get(handle)
        if existing is not None and existing != blob:
            raise ValueError(f"vault handle collision: {handle}")
        self._store[handle] = blob

    def reveal(self, handle: str) -> Optional[str]:
        blob = self._store.get(handle)
        return None if blob is None else self._xor(blob).decode("utf-8")

    def __len__(self) -> int:
        return len(self._store)


class Redactor:
    """Tokenizes incidental secrets in text and (recursively) in payloads."""

    def __init__(
        self,
        detectors: Optional[List[Detector]] = None,
        vault: Optional[SecretVault] = None,
        flag_format: Optional[str] = None,
    ) -> None:
        self.detectors = detectors if detectors is not None else DEFAULT_DETECTORS
        self.vault = vault if vault is not None else SecretVault()
        self._flag_re: Optional[Pattern[str]] = (
            re.compile(flag_format) if flag_format else None
        )

    def _is_flag(self, span: str) -> bool:
        return bool(self._flag_re and self._flag_re.fullmatch(span))

    def redact_text(self, text: str) -> Tuple[str, List[Dict[str, str]]]:
        """Return (redacted_text, [{handle, kind}, ...]).

        Handles are already present in `text` — an idempotent second pass makes
        no further changes, so redaction is safe to run more than once.
        """
        if not isinstance(text, str) or not text:
            return text, []
        redactions: Dict[str, str] = {}  # handle -> kind, dedup within one call

        for det in self.detectors:
            def _sub(m: "re.Match[str]") -> str:
                whole = m.group(0)
                secret = m.group(det.group)
                if not secret or self._is_flag(secret):
                    return whole
                handle = handle_for(det.kind, secret)
                self.vault.store(handle, secret)
                redactions[handle] = det.kind
                # replace only the secret group, keep the surrounding structure
                start, end = m.span(det.group)
                off_s, off_e = start - m.start(), end - m.start()
                return whole[:off_s] + handle + whole[off_e:]

            # Run the detector only on the gaps *between* existing handles, so a
            # newly minted handle (which contains the literal "SECRET:") can never
            # be re-matched by a later detector. re.split keeps the handle
            # delimiters, which sit at odd indices.
            parts = _HANDLE_SPLIT_RE.split(text)
            for i in range(0, len(parts), 2):
                parts[i] = det.pattern.sub(_sub, parts[i])
            text = "".join(parts)

        out = [{"handle": h, "kind": k} for h, k in redactions.items()]
        # stable order for deterministic events
        out.sort(key=lambda r: r["handle"])
        return text, out

    def redact_payload(self, payload: Any) -> Tuple[Any, List[Dict[str, str]]]:
        """Walk a JSON-ish structure, tokenizing every string value.

        Dict *keys* are structural and left untouched; only values are scanned.
        Returns the redacted copy and the merged, de-duplicated redaction list.
        """
        merged: Dict[str, str] = {}

        def _walk(node: Any, key: Optional[str] = None) -> Any:
            if isinstance(node, str):
                # A value under a sensitive key is a secret even if its shape is
                # innocuous — tokenize it wholesale (unless it's the flag).
                if key and SENSITIVE_KEY_RE.search(key) and not self._is_flag(node):
                    kind = "secret_kv"
                    handle = handle_for(kind, node)
                    self.vault.store(handle, node)
                    merged[handle] = kind
                    return handle
                red, reds = self.redact_text(node)
                for r in reds:
                    merged[r["handle"]] = r["kind"]
                return red
            if isinstance(node, dict):
                return {k: _walk(v, k) for k, v in node.items()}
            if isinstance(node, list):
                return [_walk(v, key) for v in node]
            return node

        clean = _walk(payload)
        out = [{"handle": h, "kind": k} for h, k in merged.items()]
        out.sort(key=lambda r: r["handle"])
        return clean, out


def find_handles(text: str) -> List[str]:
    """Every secret handle referenced in a piece of text (audit helper)."""
    return _HANDLE_RE.findall(text) if isinstance(text, str) else []
