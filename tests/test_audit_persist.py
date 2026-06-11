"""Trace persistence + deterministic replay across a save/load round-trip."""

from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from threat_agents.common.audit import AuditTrace
from threat_agents.common.grounding.reference_index import ReferenceIndex
from threat_agents.common.integrations.stubs import StdoutApprovalQueue
from threat_agents.common.schema import DFD, DFDElement, ElementType
from threat_agents.common.testing import stub_stride_llm
from threat_agents.graphs.d1_stride import build_d1_graph


def test_d1_trace_persists_and_replays(tmp_path):
    app = build_d1_graph(stub_stride_llm(), ReferenceIndex.from_seed(), StdoutApprovalQueue(), MemorySaver())
    cfg = {"configurable": {"thread_id": "audit-1"}}
    app.invoke(
        {"run_id": "r", "dfd": DFD(name="A", elements=[DFDElement(id="p", name="svc", type=ElementType.PROCESS)])},
        cfg,
    )
    final = app.invoke(Command(resume={"approved": True}), cfg)

    entries = AuditTrace.number(final["trace"])
    assert [e.seq for e in entries] == list(range(len(entries)))
    # version pinned on every record
    assert all(e.ref_index_version == "seed-enterprise-attack-15.1" for e in entries)

    path = tmp_path / "trace.jsonl"
    AuditTrace.to_jsonl(entries, path)
    reloaded = AuditTrace.from_jsonl(path)
    assert AuditTrace.replay_signature(reloaded) == AuditTrace.replay_signature(entries)
