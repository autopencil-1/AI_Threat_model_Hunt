"""Stage 2+ — NOT built in Stage 1.

Promoted-edges overlay (05 §2.2, store iii): versioned, human-curated, read as grounding but
tagged provenance=promoted and confidence-capped. Written ONLY via a separate OFFLINE curation
gate (multi-sign-off / quarantine) — never the runtime interrupt(). This is the C1 fix.
"""

from __future__ import annotations


class PromotedEdgesOverlay:
    def __init__(self, *args, **kwargs):
        raise NotImplementedError(
            "Stage 2 component (IMPLEMENTATION_STRATEGY.md §4 Stage 2). Promotion is an offline, "
            "audited, multi-sign-off curation surface — never a runtime write path."
        )
