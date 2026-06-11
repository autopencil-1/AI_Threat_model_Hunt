"""Stage 2+ — NOT built in Stage 1.

Append-only, sign-off-gated, provenance-tracked artifact store (05 §2.2, store ii). D2/D3/D4
outputs reused as confidence-weighted hypotheses, never as grounding. Carries provenance +
typed confidence + run_id + kg_version; deprecation-migration on ATT&CK releases.
"""

from __future__ import annotations


class ArtifactStore:
    def __init__(self, *args, **kwargs):
        raise NotImplementedError(
            "Stage 2 component (IMPLEMENTATION_STRATEGY.md §4 Stage 2)."
        )
