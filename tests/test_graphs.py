"""End-to-end graph smoke tests (offline stub LLM + MemorySaver)."""

from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from threat_agents.common.grounding.reference_index import ReferenceIndex
from threat_agents.common.integrations.stubs import StdoutApprovalQueue
from threat_agents.common.schema import DFD, DataFlow, DFDElement, ElementType
from threat_agents.common.testing import stub_stride_llm, stub_tree_llm
from threat_agents.graphs.d1_stride import build_d1_graph
from threat_agents.graphs.d3_attack_tree import build_d3_graph


def _dfd() -> DFD:
    return DFD(
        name="App",
        elements=[
            DFDElement(id="user", name="User", type=ElementType.EXTERNAL_ENTITY),
            DFDElement(id="web", name="Web", type=ElementType.PROCESS),
            DFDElement(id="ai", name="Agent", type=ElementType.PROCESS, is_ai_agent=True),
            DFDElement(id="db", name="DB", type=ElementType.DATA_STORE),
        ],
        flows=[DataFlow(id="f1", name="login", source="user", destination="web")],
    )


def test_d1_end_to_end_publishes_on_approval():
    app = build_d1_graph(stub_stride_llm(), ReferenceIndex.from_seed(), StdoutApprovalQueue(), MemorySaver())
    cfg = {"configurable": {"thread_id": "t-d1"}}

    paused = app.invoke({"run_id": "r", "dfd": _dfd()}, cfg)
    assert "__interrupt__" in paused  # halted at the human gate before publishing

    final = app.invoke(Command(resume={"approved": True}), cfg)
    assert final["threat_model"].coverage_ok is True
    assert final["ticket_id"] is not None


def test_d1_withholds_publish_on_rejection():
    app = build_d1_graph(stub_stride_llm(), ReferenceIndex.from_seed(), StdoutApprovalQueue(), MemorySaver())
    cfg = {"configurable": {"thread_id": "t-d1-reject"}}
    app.invoke({"run_id": "r", "dfd": _dfd()}, cfg)
    final = app.invoke(Command(resume={"approved": False}), cfg)
    assert final["ticket_id"] is None  # human is the disposer; no approval -> no side effect


def test_d3_end_to_end_wellformed_and_resolves_techniques():
    app = build_d3_graph(stub_tree_llm(), ReferenceIndex.from_seed(), StdoutApprovalQueue(), MemorySaver(), max_depth=3)
    cfg = {"configurable": {"thread_id": "t-d3"}}

    paused = app.invoke({"run_id": "r", "goal": "Compromise database"}, cfg)
    assert "__interrupt__" in paused

    final = app.invoke(Command(resume={"approved": True}), cfg)
    assert final["wf"].ok is True
    assert final["ticket_id"] is not None
    assert final["shadow"].gating_authority is False  # semantic critic never gates in Stage 1

    # every leaf with a technique resolves in the pinned index (invariant held)
    idx = ReferenceIndex.from_seed()
    leaves = []

    def walk(n):
        if n.refinement.value == "LEAF":
            leaves.append(n)
        for c in n.children:
            walk(c)

    walk(final["tree"])
    assert leaves
    for leaf in leaves:
        if leaf.technique_id:
            assert leaf.technique_id in idx
