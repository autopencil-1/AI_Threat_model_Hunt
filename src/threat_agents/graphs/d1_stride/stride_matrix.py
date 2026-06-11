"""STRIDE-per-element applicability matrix (classic Microsoft threat-modeling chart).

This is deterministic policy, not an LLM decision — it defines exactly which STRIDE categories
each DFD element type must be analyzed for, and is what the coverage critic checks against.
"""

from __future__ import annotations

from ...common.schema import DFDElement, ElementType, StrideCategory

S = StrideCategory.SPOOFING
T = StrideCategory.TAMPERING
R = StrideCategory.REPUDIATION
I = StrideCategory.INFO_DISCLOSURE
D = StrideCategory.DENIAL_OF_SERVICE
E = StrideCategory.ELEVATION

APPLICABILITY: dict[ElementType, frozenset[StrideCategory]] = {
    ElementType.EXTERNAL_ENTITY: frozenset({S, R}),
    ElementType.PROCESS: frozenset({S, T, R, I, D, E}),
    ElementType.DATA_STORE: frozenset({T, R, I, D}),
    ElementType.DATA_FLOW: frozenset({T, I, D}),
}


def applicable_categories(element: DFDElement) -> frozenset[StrideCategory]:
    cats = set(APPLICABILITY[element.type])
    # A data flow crossing a trust boundary warrants spoofing analysis (authn across the boundary).
    if element.type == ElementType.DATA_FLOW and element.crosses_trust_boundary:
        cats.add(StrideCategory.SPOOFING)
    if element.is_ai_agent:  # ASTRIDE "A" extension (05 §2.1)
        cats.add(StrideCategory.AI_AGENT)
    return frozenset(cats)
