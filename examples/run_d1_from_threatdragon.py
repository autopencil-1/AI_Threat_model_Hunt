"""Import an OWASP Threat Dragon model and run D1 on it, offline (stub LLM).

    python examples/run_d1_from_threatdragon.py

Shows the importer end-to-end: parse a .json model -> DFD -> D1 STRIDE graph. The login flow
crosses the trust boundary, so it picks up the Spoofing category; the LLM process is flagged
is_ai_agent and gets the ASTRIDE "A" category; the out-of-scope cell is dropped.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from langgraph.checkpoint.memory import MemorySaver  # noqa: E402
from langgraph.types import Command  # noqa: E402

from threat_agents.common.grounding.reference_index import ReferenceIndex  # noqa: E402
from threat_agents.common.integrations.stubs import StdoutApprovalQueue  # noqa: E402
from threat_agents.common.testing import stub_stride_llm  # noqa: E402
from threat_agents.graphs.d1_stride import build_d1_graph, load_threat_dragon  # noqa: E402

SAMPLE = pathlib.Path(__file__).parent / "threat_dragon_sample.json"


def main() -> None:
    dfd = load_threat_dragon(SAMPLE)
    print(f"Imported '{dfd.name}': {len(dfd.elements)} elements, {len(dfd.flows)} flows, "
          f"{len(dfd.boundaries)} boundaries")
    for f in dfd.flows:
        print(f"  flow {f.name}: crosses_trust_boundary={f.crosses_trust_boundary}")

    app = build_d1_graph(stub_stride_llm(), ReferenceIndex.from_seed(), StdoutApprovalQueue(), MemorySaver())
    cfg = {"configurable": {"thread_id": "td-d1"}}
    app.invoke({"run_id": "td-001", "dfd": dfd}, cfg)
    final = app.invoke(Command(resume={"approved": True}), cfg)
    tm = final["threat_model"]
    print(f"\ncoverage_ok={tm.coverage_ok}  threats={len(tm.threats)}  ticket={final.get('ticket_id')}")


if __name__ == "__main__":
    main()
