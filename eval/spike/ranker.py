"""Ranker interface + a baseline implementation for the spike.

`Ranker` is the seam where Stage 2's **frozen-weight non-LLM re-ranker over the KG frontier**
(05 §2.3 / B4) plugs in. `LexicalRanker` is a deterministic BASELINE (set-cosine over technique
name + description over the whole index) so the harness runs offline today and its metrics/plumbing
are validated before the real ranker and KG exist. Baseline numbers are NOT decision-grade.
"""

from __future__ import annotations

import math
import re
from typing import Protocol, runtime_checkable

from threat_agents.common.grounding.reference_index import ReferenceIndex

_TOK = re.compile(r"[a-z0-9]+")
_STOP = {
    "the", "a", "an", "of", "to", "and", "or", "in", "on", "for", "with", "by", "from", "as", "at",
    "is", "are", "was", "were", "be", "that", "this", "via", "using", "used", "over", "into",
    "across", "single", "multiple", "new", "an", "it", "its", "their", "they", "we", "observed",
}


def tokens(text: str) -> set[str]:
    return {t for t in _TOK.findall(text.lower()) if len(t) >= 2 and t not in _STOP}


@runtime_checkable
class Ranker(Protocol):
    def rank(self, query: str, k: int = 10) -> list[tuple[str, float]]:
        """Return up to k (technique_id, score) pairs, score in (0,1], descending."""
        ...


class LexicalRanker:
    def __init__(self, index: ReferenceIndex):
        self.index = index
        self._content: list[tuple[str, frozenset[str]]] = [
            (t.id, frozenset(tokens(f"{t.name} {t.description}"))) for t in index.all()
        ]

    def rank(self, query: str, k: int = 10) -> list[tuple[str, float]]:
        q = tokens(query)
        if not q:
            return []
        scored: list[tuple[str, float]] = []
        for tid, content in self._content:
            if not content:
                continue
            inter = len(q & content)
            if inter == 0:
                continue
            score = inter / math.sqrt(len(q) * len(content))
            scored.append((tid, score))
        scored.sort(key=lambda x: (-x[1], x[0]))  # tie-break by id -> deterministic
        return scored[:k]
