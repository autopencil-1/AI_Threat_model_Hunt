"""Durable-checkpointer tests, incl. resume across separate saver instances on the same DB."""

from langgraph.types import Command

from threat_agents.common.checkpointer import make_checkpointer
from threat_agents.common.grounding.reference_index import ReferenceIndex
from threat_agents.common.integrations.stubs import StdoutApprovalQueue
from threat_agents.common.schema import DFD, DFDElement, ElementType
from threat_agents.common.testing import stub_stride_llm
from threat_agents.graphs.d1_stride import build_d1_graph


def _dfd() -> DFD:
    return DFD(name="App", elements=[DFDElement(id="web", name="Web", type=ElementType.PROCESS)])


def test_memory_kind():
    from langgraph.checkpoint.memory import MemorySaver

    assert isinstance(make_checkpointer("memory"), MemorySaver)


def test_unknown_kind_raises():
    import pytest

    with pytest.raises(ValueError):
        make_checkpointer("redis")


def test_sqlite_durability_resume_across_instances(tmp_path):
    db = str(tmp_path / "cp.sqlite")
    cfg = {"configurable": {"thread_id": "durable-1"}}

    # Instance 1: run until the human gate, then the process "ends".
    cp1 = make_checkpointer("sqlite", db)
    app1 = build_d1_graph(stub_stride_llm(), ReferenceIndex.from_seed(), StdoutApprovalQueue(), cp1)
    paused = app1.invoke({"run_id": "r", "dfd": _dfd()}, cfg)
    assert "__interrupt__" in paused

    # Instance 2: brand-new saver on the SAME db file resumes the interrupted run.
    cp2 = make_checkpointer("sqlite", db)
    app2 = build_d1_graph(stub_stride_llm(), ReferenceIndex.from_seed(), StdoutApprovalQueue(), cp2)
    final = app2.invoke(Command(resume={"approved": True}), cfg)
    assert final["threat_model"].coverage_ok is True
    assert final["ticket_id"] is not None
