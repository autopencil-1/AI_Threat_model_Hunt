import json

from threat_agents.common.schema import ElementType
from threat_agents.graphs.d1_stride import load_threat_dragon, parse_threat_dragon

_MODEL = {
    "summary": {"title": "T"},
    "detail": {
        "diagrams": [
            {
                "title": "d",
                "cells": [
                    {"id": "box", "shape": "trust-boundary-box", "position": {"x": 200, "y": 0},
                     "size": {"width": 500, "height": 500}, "data": {"type": "tm.BoundaryBox", "name": "Zone"}},
                    {"id": "user", "shape": "actor", "position": {"x": 0, "y": 200},
                     "size": {"width": 100, "height": 100}, "data": {"type": "tm.Actor", "name": "User"}},
                    {"id": "web", "shape": "process", "position": {"x": 300, "y": 100},
                     "size": {"width": 100, "height": 100}, "data": {"type": "tm.Process", "name": "Web"}},
                    {"id": "ai", "shape": "process", "position": {"x": 500, "y": 100},
                     "size": {"width": 100, "height": 100}, "data": {"type": "tm.Process", "name": "Agent", "isAIAgent": True}},
                    {"id": "db", "shape": "store", "position": {"x": 300, "y": 300},
                     "size": {"width": 100, "height": 100}, "data": {"type": "tm.Store", "name": "DB"}},
                    {"id": "gone", "shape": "process", "position": {"x": 900, "y": 900},
                     "size": {"width": 10, "height": 10}, "data": {"type": "tm.Process", "name": "OOS", "outOfScope": True}},
                    {"id": "f1", "shape": "flow", "source": {"cell": "user"}, "target": {"cell": "web"},
                     "data": {"type": "tm.Flow", "name": "login"}},
                    {"id": "f2", "shape": "flow", "source": {"cell": "web"}, "target": {"cell": "db"},
                     "data": {"type": "tm.Flow", "name": "query"}},
                ],
            }
        ]
    },
}


def test_element_mapping_and_out_of_scope():
    dfd = parse_threat_dragon(_MODEL)
    by_id = {e.id: e for e in dfd.elements}
    assert by_id["user"].type == ElementType.EXTERNAL_ENTITY
    assert by_id["web"].type == ElementType.PROCESS
    assert by_id["db"].type == ElementType.DATA_STORE
    assert by_id["ai"].is_ai_agent is True
    assert "gone" not in by_id  # out-of-scope dropped


def test_geometric_trust_boundary_crossing():
    dfd = parse_threat_dragon(_MODEL)
    flows = {f.id: f for f in dfd.flows}
    assert flows["f1"].crosses_trust_boundary is True   # user outside, web inside the box
    assert flows["f2"].crosses_trust_boundary is False  # web + db both inside


def test_boundary_membership():
    dfd = parse_threat_dragon(_MODEL)
    zone = next(b for b in dfd.boundaries if b.id == "box")
    assert set(zone.member_ids) == {"web", "ai", "db"}
    assert "user" not in zone.member_ids


def test_load_from_file(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps(_MODEL), encoding="utf-8")
    dfd = load_threat_dragon(p)
    assert dfd.name == "T"
    assert len(dfd.elements) == 4 and len(dfd.flows) == 2


def test_imported_dfd_runs_through_d1():
    # the crossing login flow must pick up Spoofing; the AI process must require category A
    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.types import Command

    from threat_agents.common.grounding.reference_index import ReferenceIndex
    from threat_agents.common.integrations.stubs import StdoutApprovalQueue
    from threat_agents.common.schema import StrideCategory
    from threat_agents.common.testing import stub_stride_llm
    from threat_agents.graphs.d1_stride import build_d1_graph

    dfd = parse_threat_dragon(_MODEL)
    app = build_d1_graph(stub_stride_llm(), ReferenceIndex.from_seed(), StdoutApprovalQueue(), MemorySaver())
    cfg = {"configurable": {"thread_id": "td-test"}}
    app.invoke({"run_id": "r", "dfd": dfd}, cfg)
    final = app.invoke(Command(resume={"approved": True}), cfg)
    tm = final["threat_model"]
    assert tm.coverage_ok
    f1_cats = {t.category for t in tm.threats if t.element_id == "f1"}
    assert StrideCategory.SPOOFING in f1_cats  # crossing flow -> spoofing
    ai_cats = {t.category for t in tm.threats if t.element_id == "ai"}
    assert StrideCategory.AI_AGENT in ai_cats  # is_ai_agent -> ASTRIDE "A"
