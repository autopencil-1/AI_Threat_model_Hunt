"""Ranker interface + a baseline implementation for the spike.

`Ranker` is the seam where Stage 2's **frozen-weight non-LLM re-ranker over the KG frontier**
(05 §2.3 / B4) plugs in. `LexicalRanker` is a deterministic BASELINE (set-cosine over technique
name + description over the whole index) so the harness runs offline today and its metrics/plumbing
are validated before the real ranker and KG exist. Baseline numbers are NOT decision-grade.
"""

from __future__ import annotations

import math
import re
from typing import Callable, Protocol, runtime_checkable

from threat_agents.common.grounding.reference_index import ReferenceIndex

DEFAULT_CROSS_ENCODER = "cross-encoder/ms-marco-MiniLM-L-6-v2"

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


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


_MODEL_CACHE: dict[str, object] = {}


def _load_cross_encoder(model_name: str):
    if model_name not in _MODEL_CACHE:
        from sentence_transformers import CrossEncoder  # lazy: optional dep (extras: crossencoder)

        _MODEL_CACHE[model_name] = CrossEncoder(model_name)
    return _MODEL_CACHE[model_name]


def _default_scorer(model_name: str) -> Callable[[list[tuple[str, str]]], list[float]]:
    def scorer(pairs: list[tuple[str, str]]) -> list[float]:
        return [float(x) for x in _load_cross_encoder(model_name).predict(pairs)]

    return scorer


class CrossEncoderRanker:
    """Frozen non-LLM cross-encoder re-ranker (B4) over a cheap prefilter — Stage-2 Tier-1 shape.

    Two stages, exactly as the production Tier-1 will be: a cheap prefilter narrows the candidate set
    (here `LexicalRanker` over the index; in Stage 2 this is the KG-frontier traversal), then a
    FROZEN cross-encoder re-ranks that shortlist. Deterministic given pinned weights + eval mode; no
    generation, no sampling — this is what lets Tier-1 keep its cost/determinism/replay claims.

    `scorer` is injectable so the ranking logic is testable without torch; the default lazily loads a
    sentence-transformers CrossEncoder (optional `crossencoder` extra).
    """

    def __init__(
        self,
        index: ReferenceIndex,
        prefilter: "Ranker | None" = None,
        prefilter_k: int = 50,
        model_name: str = DEFAULT_CROSS_ENCODER,
        scorer: Callable[[list[tuple[str, str]]], list[float]] | None = None,
    ):
        self.index = index
        self.prefilter = prefilter or LexicalRanker(index)
        self.prefilter_k = prefilter_k
        self.model_name = model_name
        self._scorer = scorer or _default_scorer(model_name)
        self._text = {t.id: f"{t.name}. {t.description}".strip(". ") for t in index.all()}

    def rank(self, query: str, k: int = 10) -> list[tuple[str, float]]:
        cand_ids = [tid for tid, _ in self.prefilter.rank(query, self.prefilter_k)]
        if not cand_ids:
            return []
        pairs = [(query, self._text.get(tid, tid)) for tid in cand_ids]
        raw = self._scorer(pairs)
        scored = [(tid, _sigmoid(float(s))) for tid, s in zip(cand_ids, raw)]
        scored.sort(key=lambda x: (-x[1], x[0]))  # deterministic
        return scored[:k]
