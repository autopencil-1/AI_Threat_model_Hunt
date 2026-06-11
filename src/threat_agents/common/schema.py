"""Typed domain model shared across graphs.

Pydantic models so inputs are validated at the boundary (the framework constrains; the LLM
only fills bounded fields). The richer cross-task types (PivotRequest, full KG refs) are
Stage 3+; Stage 1 uses the subset below plus a minimal `ConfidenceRecord` carried for forward
compatibility (05 §2.7 / C4).
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------------------
# D1 — STRIDE / DFD
# --------------------------------------------------------------------------------------
class StrideCategory(str, Enum):
    SPOOFING = "S"
    TAMPERING = "T"
    REPUDIATION = "R"
    INFO_DISCLOSURE = "I"
    DENIAL_OF_SERVICE = "D"
    ELEVATION = "E"
    AI_AGENT = "A"  # ASTRIDE extension for AI-agent elements (05 §2.1)


class ElementType(str, Enum):
    EXTERNAL_ENTITY = "external_entity"
    PROCESS = "process"
    DATA_STORE = "data_store"
    DATA_FLOW = "data_flow"


class DFDElement(BaseModel):
    id: str
    name: str
    type: ElementType
    is_ai_agent: bool = False


class DataFlow(BaseModel):
    id: str
    name: str
    source: str
    destination: str
    crosses_trust_boundary: bool = False


class TrustBoundary(BaseModel):
    id: str
    name: str
    member_ids: list[str] = Field(default_factory=list)


class DFD(BaseModel):
    name: str
    elements: list[DFDElement]
    flows: list[DataFlow] = Field(default_factory=list)
    boundaries: list[TrustBoundary] = Field(default_factory=list)

    def stride_elements(self) -> list[DFDElement]:
        """DFD elements AND data-flows — every one is a STRIDE-per-element target."""
        flow_elems = [
            DFDElement(id=f.id, name=f.name, type=ElementType.DATA_FLOW) for f in self.flows
        ]
        return list(self.elements) + flow_elems


class Threat(BaseModel):
    id: str
    element_id: str
    category: StrideCategory
    description: str
    technique_ids: list[str] = Field(default_factory=list)
    mitigation: Optional[str] = None


class ThreatModel(BaseModel):
    dfd_name: str
    threats: list[Threat]
    coverage_ok: bool
    gaps: list[tuple[str, str]] = Field(default_factory=list)  # (element_id, category code)


# --------------------------------------------------------------------------------------
# D3 — Attack tree (Schneier AND/OR, +SAND)
# --------------------------------------------------------------------------------------
class Refinement(str, Enum):
    AND = "AND"
    OR = "OR"
    SAND = "SAND"
    LEAF = "LEAF"


class AttackTreeNode(BaseModel):
    id: str
    goal: str
    refinement: Refinement
    children: list["AttackTreeNode"] = Field(default_factory=list)
    technique_id: Optional[str] = None


AttackTreeNode.model_rebuild()


# --------------------------------------------------------------------------------------
# Shared grounding / confidence (minimal in Stage 1; full use Stage 3+)
# --------------------------------------------------------------------------------------
class Provenance(str, Enum):
    BASE = "base"
    PROMOTED = "promoted"  # confidence-capped (05 §2.2 / C1)
    ARTIFACT = "artifact"


class CriticVerdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ABSTAIN = "abstain"


class ConfidenceRecord(BaseModel):
    """Typed confidence record (05 §2.7 / C4) — replaces any scalar 'confidence floor'.
    No threshold over these fields is set until they are calibrated (reliability diagram)."""

    retrieval_relevance: float = 0.0
    attribution_class_ceiling: float = 1.0
    reuse_chain_confidences: list[float] = Field(default_factory=list)
    critic_verdict: CriticVerdict = CriticVerdict.ABSTAIN
    provenance: Provenance = Provenance.BASE


class KGRef(BaseModel):
    technique_id: str
    object_ref: str
    kg_version: str


class Finding(BaseModel):
    id: str
    summary: str
    technique_ids: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------------------
# Audit / trace
# --------------------------------------------------------------------------------------
class TraceNode(BaseModel):
    """One replayable trace record. `ref_index_version` is the Stage-1 analogue of `kg_version`
    (05 §2.2 / C2): deterministic replay loads the PINNED version, never 'current'."""

    run_id: str
    ref_index_version: str
    graph: str
    node: str
    action: str
    detail: dict = Field(default_factory=dict)
    confidence: Optional[ConfidenceRecord] = None
    seq: Optional[int] = None
    ts: Optional[str] = None  # wall-clock; EXCLUDED from replay equality
