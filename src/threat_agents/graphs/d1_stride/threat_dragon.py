"""OWASP Threat Dragon (v2) model importer -> our DFD.

Maps Threat Dragon diagram cells to `DFDElement` / `DataFlow` / `TrustBoundary`:
  tm.Actor -> EXTERNAL_ENTITY · tm.Process -> PROCESS · tm.Store -> DATA_STORE ·
  tm.Flow -> DataFlow · tm.Boundary(Box) -> TrustBoundary.

`crosses_trust_boundary` is computed geometrically: a flow crosses if its source and target fall
in different sets of trust-boundary-BOXES (by element center vs box rect). Curve boundaries carry
no geometry, so they don't drive crossing (documented limitation). `is_ai_agent` is read from a
`data.isAIAgent: true` convention (Threat Dragon has no native AI-agent stencil). Out-of-scope cells
are skipped.
"""

from __future__ import annotations

import json
from pathlib import Path

from ...common.schema import DFD, DataFlow, DFDElement, ElementType, TrustBoundary

_TYPE_MAP = {
    "tm.Actor": ElementType.EXTERNAL_ENTITY,
    "tm.Process": ElementType.PROCESS,
    "tm.Store": ElementType.DATA_STORE,
}
_SHAPE_MAP = {
    "actor": ElementType.EXTERNAL_ENTITY,
    "process": ElementType.PROCESS,
    "store": ElementType.DATA_STORE,
}
_FLOW_TYPES = {"tm.Flow"}
_FLOW_SHAPES = {"flow"}
_BOX_TYPES = {"tm.BoundaryBox"}
_BOX_SHAPES = {"trust-boundary-box"}
_CURVE_TYPES = {"tm.Boundary"}
_CURVE_SHAPES = {"trust-boundary-curve"}


def _center(cell: dict) -> tuple[float, float] | None:
    p = cell.get("position") or {}
    s = cell.get("size") or {}
    if "x" not in p or "y" not in p:
        return None
    return (p["x"] + s.get("width", 0) / 2, p["y"] + s.get("height", 0) / 2)


def _rect(cell: dict) -> tuple[float, float, float, float] | None:
    p = cell.get("position") or {}
    s = cell.get("size") or {}
    if "x" not in p or "y" not in p:
        return None
    return (p["x"], p["y"], s.get("width", 0), s.get("height", 0))


def _contains(rect: tuple[float, float, float, float], pt: tuple[float, float]) -> bool:
    x, y, w, h = rect
    return x <= pt[0] <= x + w and y <= pt[1] <= y + h


def _kind(cell: dict) -> tuple[str, str]:
    return (cell.get("data", {}) or {}).get("type", ""), cell.get("shape", "")


def parse_threat_dragon(model: dict, diagram_index: int = 0) -> DFD:
    diagrams = (model.get("detail") or {}).get("diagrams") or []
    if not diagrams:
        raise ValueError("Threat Dragon model has no diagrams")
    diagram = diagrams[diagram_index]
    cells = diagram.get("cells") or (diagram.get("diagramJson") or {}).get("cells") or []
    name = (model.get("summary") or {}).get("title") or diagram.get("title") or "Threat Dragon model"

    elements: list[DFDElement] = []
    centers: dict[str, tuple[float, float]] = {}
    boxes: list[tuple[str, str, tuple]] = []  # (id, name, rect)
    curves: list[tuple[str, str]] = []
    raw_flows: list[tuple[str, str, str | None, str | None]] = []

    for cell in cells:
        data = cell.get("data") or {}
        if data.get("outOfScope"):
            continue
        ttype, shape = _kind(cell)
        cid = str(cell.get("id"))
        cname = data.get("name") or shape or cid

        etype = _TYPE_MAP.get(ttype) or _SHAPE_MAP.get(shape)
        if etype is not None:
            elements.append(
                DFDElement(id=cid, name=cname, type=etype, is_ai_agent=bool(data.get("isAIAgent")))
            )
            c = _center(cell)
            if c:
                centers[cid] = c
        elif ttype in _FLOW_TYPES or shape in _FLOW_SHAPES:
            src = (cell.get("source") or {}).get("cell")
            tgt = (cell.get("target") or {}).get("cell")
            raw_flows.append((cid, cname, str(src) if src else None, str(tgt) if tgt else None))
        elif ttype in _BOX_TYPES or shape in _BOX_SHAPES:
            r = _rect(cell)
            if r:
                boxes.append((cid, cname, r))
        elif ttype in _CURVE_TYPES or shape in _CURVE_SHAPES:
            curves.append((cid, cname))
        # other shapes (text, etc.) ignored

    def boxes_of(eid: str | None) -> frozenset[str]:
        if eid is None or eid not in centers:
            return frozenset()
        return frozenset(bid for bid, _, r in boxes if _contains(r, centers[eid]))

    flows: list[DataFlow] = []
    for fid, fname, src, tgt in raw_flows:
        crosses = src is not None and tgt is not None and boxes_of(src) != boxes_of(tgt)
        flows.append(
            DataFlow(id=fid, name=fname, source=src or "", destination=tgt or "",
                     crosses_trust_boundary=crosses)
        )

    boundaries = [
        TrustBoundary(id=bid, name=bname,
                      member_ids=[eid for eid in centers if _contains(r, centers[eid])])
        for bid, bname, r in boxes
    ] + [TrustBoundary(id=cid, name=cname) for cid, cname in curves]

    return DFD(name=name, elements=elements, flows=flows, boundaries=boundaries)


def load_threat_dragon(path, diagram_index: int = 0) -> DFD:
    model = json.loads(Path(path).read_text(encoding="utf-8"))
    return parse_threat_dragon(model, diagram_index=diagram_index)
