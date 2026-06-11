"""Run the D3 attack-tree graph end-to-end, offline (stub LLM). No API key needed.

    python examples/run_d3.py

Demonstrates: recursive Send fan-out per frontier, the depth/loop guard, the deterministic
well-formedness critic gating, the semantic critic running in SHADOW mode (no gating
authority), the interrupt() gate, resume, and publish.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from langgraph.checkpoint.memory import MemorySaver  # noqa: E402
from langgraph.types import Command  # noqa: E402

from threat_agents.common.grounding.reference_index import ReferenceIndex  # noqa: E402
from threat_agents.common.integrations.stubs import StdoutApprovalQueue  # noqa: E402
from threat_agents.common.schema import AttackTreeNode  # noqa: E402
from threat_agents.common.testing import stub_tree_llm  # noqa: E402
from threat_agents.graphs.d3_attack_tree import build_d3_graph  # noqa: E402


def _print_tree(n: AttackTreeNode, depth: int = 0) -> None:
    tid = f"  [{n.technique_id}]" if n.technique_id else ""
    print(f"{'  ' * depth}- ({n.refinement.value}) {n.goal}{tid}")
    for c in n.children:
        _print_tree(c, depth + 1)


def main() -> None:
    app = build_d3_graph(stub_tree_llm(), ReferenceIndex.from_seed(), StdoutApprovalQueue(), MemorySaver())
    cfg = {"configurable": {"thread_id": "demo-d3"}}

    paused = app.invoke({"run_id": "d3-001", "goal": "Exfiltrate the customer database"}, cfg)
    intr = paused.get("__interrupt__")
    if intr:
        sc = intr[0].value["shadow_critic"]
        print(f"\n[gate] paused — {intr[0].value['summary']}")
        print(f"[gate] shadow critic verdict={sc['verdict']} gating_authority={sc['gating_authority']}")

    final = app.invoke(Command(resume={"approved": True, "by": "analyst"}), cfg)
    print(f"\nwell-formed={final['wf'].ok}  ticket={final.get('ticket_id')}\n")
    _print_tree(final["tree"])


if __name__ == "__main__":
    main()
