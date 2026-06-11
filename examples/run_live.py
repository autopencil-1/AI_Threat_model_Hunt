"""Run D1 and D3 against the REAL Anthropic API.

    python examples/run_live.py

Loads `.env` (ANTHROPIC_API_KEY etc.), then drives both graphs with `AnthropicLLM`. Kept small
(few elements, shallow tree) to bound cost. Uses ANTHROPIC_DEFAULT_MODEL for the worker; the D3
semantic critic ideally uses a *different* model (independence lever, C5) but falls back to the
same model here if that's all the key can reach.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from langgraph.checkpoint.memory import MemorySaver  # noqa: E402
from langgraph.types import Command  # noqa: E402

from threat_agents.common.config import anthropic_default_model, load_env  # noqa: E402
from threat_agents.common.grounding.reference_index import ReferenceIndex  # noqa: E402
from threat_agents.common.integrations.stubs import StdoutApprovalQueue  # noqa: E402
from threat_agents.common.llm import AnthropicLLM  # noqa: E402
from threat_agents.common.schema import DFD, AttackTreeNode, DataFlow, DFDElement, ElementType  # noqa: E402
from threat_agents.graphs.d1_stride import build_d1_graph  # noqa: E402
from threat_agents.graphs.d3_attack_tree import build_d3_graph  # noqa: E402


def _print_tree(n: AttackTreeNode, depth: int = 0) -> None:
    tid = f"  [{n.technique_id}]" if n.technique_id else ""
    print(f"{'  ' * depth}- ({n.refinement.value}) {n.goal}{tid}")
    for c in n.children:
        _print_tree(c, depth + 1)


def main() -> None:
    loaded = load_env()
    if "ANTHROPIC_API_KEY" not in {**loaded}:
        import os

        if "ANTHROPIC_API_KEY" not in os.environ:
            sys.exit("No ANTHROPIC_API_KEY found (.env or environment).")
    model = anthropic_default_model()
    print(f"Using model: {model}\n")
    llm = AnthropicLLM(default_model=model)
    index = ReferenceIndex.from_seed()

    # ---- D1 (small DFD: 2 elements) ----
    print("===== D1 STRIDE (live) =====")
    dfd = DFD(
        name="Login Service",
        elements=[
            DFDElement(id="user", name="End User", type=ElementType.EXTERNAL_ENTITY),
            DFDElement(id="auth", name="Auth Service", type=ElementType.PROCESS),
        ],
        flows=[DataFlow(id="f1", name="credentials", source="user", destination="auth", crosses_trust_boundary=True)],
    )
    d1 = build_d1_graph(llm, index, StdoutApprovalQueue(), MemorySaver(), model=model)
    cfg1 = {"configurable": {"thread_id": "live-d1"}}
    res = d1.invoke({"run_id": "live-d1", "dfd": dfd}, cfg1)
    if "__interrupt__" in res:
        print(f"[gate] {res['__interrupt__'][0].value['summary']}")
        res = d1.invoke(Command(resume={"approved": True, "by": "live-analyst"}), cfg1)
    tm = res["threat_model"]
    print(f"coverage_ok={tm.coverage_ok}  threats={len(tm.threats)}  gaps={tm.gaps}")
    for t in tm.threats:
        print(f"  {t.element_id:5} [{t.category.value}] {t.description[:80]}  {t.technique_ids}")

    # ---- D3 (shallow tree) ----
    print("\n===== D3 attack-tree (live) =====")
    d3 = build_d3_graph(llm, index, StdoutApprovalQueue(), MemorySaver(), model=model, critic_model=model, max_depth=2)
    cfg3 = {"configurable": {"thread_id": "live-d3"}}
    res = d3.invoke({"run_id": "live-d3", "goal": "Gain unauthorized access to the auth service"}, cfg3)
    if "__interrupt__" in res:
        sc = res["__interrupt__"][0].value["shadow_critic"]
        print(f"[gate] shadow critic verdict={sc['verdict']} gating_authority={sc['gating_authority']}")
        res = d3.invoke(Command(resume={"approved": True, "by": "live-analyst"}), cfg3)
    print(f"well-formed={res['wf'].ok}  violations={res['wf'].violations}\n")
    _print_tree(res["tree"])


if __name__ == "__main__":
    main()
