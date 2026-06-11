"""Stage 2+ — NOT built in Stage 1. Gated behind the §A.2 decision spike.

Versioned, content-addressed, read-only base KG (CVE→CWE→CAPEC→ATT&CK) with a frozen-weight
non-LLM re-ranker and hierarchical retrieval (05 §2.2). No runtime agent write path.
"""

from __future__ import annotations


class BaseKnowledgeGraph:
    def __init__(self, *args, **kwargs):
        raise NotImplementedError(
            "Stage 2 component. Build only after the Stage-1 value gate AND the offline "
            "miss-rate τ-sweep + re-ranker-accuracy spike support a tiered shape "
            "(IMPLEMENTATION_STRATEGY.md §Decision Gate)."
        )
