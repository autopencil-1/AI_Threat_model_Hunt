"""Run the D1 STRIDE graph end-to-end, offline (stub LLM). No API key needed.

    python examples/run_d1.py

Demonstrates: Send fan-out per DFD element, deterministic coverage critic gating, the
interrupt() gate (human as disposer), resume, and publish into the stub approval queue.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from langgraph.checkpoint.memory import MemorySaver  # noqa: E402
from langgraph.types import Command  # noqa: E402

from threat_agents.common.audit import AuditTrace  # noqa: E402
from threat_agents.common.grounding.reference_index import ReferenceIndex  # noqa: E402
from threat_agents.common.integrations.stubs import StdoutApprovalQueue  # noqa: E402
from threat_agents.common.schema import DFD, DataFlow, DFDElement, ElementType  # noqa: E402
from threat_agents.common.testing import stub_stride_llm  # noqa: E402
from threat_agents.graphs.d1_stride import build_d1_graph  # noqa: E402


def main() -> None:
    dfd = DFD(
        name="Customer Web App",
        elements=[
            DFDElement(id="user", name="Customer", type=ElementType.EXTERNAL_ENTITY),
            DFDElement(id="web", name="Web Service", type=ElementType.PROCESS),
            DFDElement(id="ai", name="Support Agent (LLM)", type=ElementType.PROCESS, is_ai_agent=True),
            DFDElement(id="db", name="Customer DB", type=ElementType.DATA_STORE),
        ],
        flows=[DataFlow(id="f1", name="login", source="user", destination="web", crosses_trust_boundary=True)],
    )

    app = build_d1_graph(stub_stride_llm(), ReferenceIndex.from_seed(), StdoutApprovalQueue(), MemorySaver())
    cfg = {"configurable": {"thread_id": "demo-d1"}}

    paused = app.invoke({"run_id": "d1-001", "dfd": dfd}, cfg)
    intr = paused.get("__interrupt__")
    print(f"\n[gate] paused at human interrupt — {intr[0].value['summary'] if intr else 'n/a'}")

    final = app.invoke(Command(resume={"approved": True, "by": "analyst"}), cfg)
    tm = final["threat_model"]
    print(f"\ncoverage_ok={tm.coverage_ok}  threats={len(tm.threats)}  ticket={final.get('ticket_id')}")
    for t in tm.threats:
        sev = f" sev={t.severity}" if t.severity else ""
        na = "" if t.applicable else " [N/A]"
        print(f"  {t.element_id:5} [{t.category.value}]{sev}{na} {t.description}  techniques={t.technique_ids}")
    print(f"\nconfidence: {final['confidence'].model_dump()}")
    print(f"trace nodes: {len(AuditTrace.number(final['trace']))}")


if __name__ == "__main__":
    main()
