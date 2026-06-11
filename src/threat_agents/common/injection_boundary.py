"""The ONE hardened indirect-prompt-injection ingestion boundary (05 §2.2).

Single entry point for adversary-controlled artifacts (CTI, web, logs). Stage-1 defenses:
size bounding, control-character stripping, and deterministic hash-pseudonymization of
identifiers (Policy-Guided shape). Output/least-privilege filtering and an adversarial test
set are layered on here too as the input surface grows.

HONEST LIMIT (05 §2.2, §6 / B6): this stops pattern-matchable payloads and normalizes input.
It does NOT stop a semantically plausible, cleanly-grounding malicious pivot — a rational
injector steers toward a real, on-graph, citable decoy that passes every grounding check.
That residual ("on-graph misdirection") is documented, not closed.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


@dataclass
class Sanitized:
    text: str
    redactions: dict = field(default_factory=dict)
    truncated: bool = False


class IngestionBoundary:
    def __init__(self, max_bytes: int = 200_000, salt: str = "stage1"):
        self.max_bytes = max_bytes
        self._salt = salt

    def _pseudo(self, kind: str, value: str) -> str:
        h = hashlib.sha256((self._salt + value).encode()).hexdigest()[:10]
        return f"<{kind}:{h}>"

    def sanitize(self, text: str) -> Sanitized:
        truncated = False
        raw = text.encode("utf-8", "replace")
        if len(raw) > self.max_bytes:
            text = raw[: self.max_bytes].decode("utf-8", "ignore")
            truncated = True
        text = _CONTROL.sub("", text)

        redactions: dict[str, int] = {}

        def _sub(pattern: re.Pattern, kind: str, s: str) -> str:
            count = 0

            def repl(m: re.Match) -> str:
                nonlocal count
                count += 1
                return self._pseudo(kind, m.group(0))

            out = pattern.sub(repl, s)
            if count:
                redactions[kind] = count
            return out

        text = _sub(_IP, "ip", text)
        text = _sub(_EMAIL, "email", text)
        return Sanitized(text=text, redactions=redactions, truncated=truncated)
