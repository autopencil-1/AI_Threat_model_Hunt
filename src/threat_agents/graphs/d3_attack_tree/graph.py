"""D3 — Recursive AND/OR attack-tree graph.

Topology: recursive orchestrator-worker. `expand_root` refines the goal and `Send`-fans out one
worker per frontier (root child); each worker builds its subtree under a depth/loop guard.
Subtrees are assembled, then the DETERMINISTIC well-formedness critic gates while the SEMANTIC
refinement critic runs in shadow (no gating authority, 05 §2.4 / C5). `interrupt()` before
publish. The framework owns control flow; the LLM only proposes refinements inside workers.

Stage-1 simplification (documented): full per-node `Send` recursion is approximated by
`Send`-per-root-child + bounded in-worker recursion. This terminates cleanly and parallelizes;
moving to per-node `Send` recursion with an explicit join is a Stage-3 refinement.
"""

from __future__ import annotations

import operator
from typing import Annotated, Optional, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, Send, interrupt

from ...common.audit import trace_entry
from ...common.grounding.reference_index import ReferenceIndex
from ...common.integrations.base import ApprovalQueueAdapter
from ...common.llm import CRITIC_MODEL, DEFAULT_MODEL, LLMClient, parse_json
from ...common.schema import AttackTreeNode, Refinement, TraceNode
from .critic import (
    ShadowResult,
    WellFormednessResult,
    semantic_refinement_critic,
    well_formedness_critic,
)

GRAPH = "D3-ATTACK-TREE"

_SYS = (
    "You are an attack-tree analyst (Schneier AND/OR refinement). Refine the given goal into its "
    "next level. Output STRICT JSON with keys "
    '"refinement","children","technique_id". "refinement" is one of AND|OR|SAND|LEAF; "children" '
    'is a list of sub-goal strings (empty for LEAF); "technique_id" is a MITRE ATT&CK ID for a '
    "LEAF or null. No prose outside the JSON."
)


class D3State(TypedDict, total=False):
    run_id: str
    ref_index_version: str
    goal: str
    max_depth: int
    node_id: str  # per-worker payload
    depth: int  # per-worker payload
    root: AttackTreeNode
    subtrees: Annotated[list[AttackTreeNode], operator.add]
    tree: AttackTreeNode
    wf: WellFormednessResult
    shadow: ShadowResult
    trace: Annotated[list[TraceNode], operator.add]
    disposition: dict
    ticket_id: Optional[str]


def _prompt(goal: str, depth: int, max_depth: int, node_id: str, hint: str) -> str:
    return (
        f"Goal: {goal}\nCurrent depth: {depth}\nMax depth: {max_depth}\n\n"
        f"For a LEAF, set technique_id to ONE technique (or null). {hint}\n\n"
        f'[[TREE id="{node_id}" depth="{depth}" max_depth="{max_depth}" goal="{goal}"]]'
    )


def build_d3_graph(
    llm: LLMClient,
    index: ReferenceIndex,
    approval_queue: ApprovalQueueAdapter,
    checkpointer,
    model: str = DEFAULT_MODEL,
    critic_model: str = CRITIC_MODEL,
    max_depth: int = 3,
):
    hint = index.grounding_hint()

    def _refine(goal: str, depth: int, node_id: str):
        data = parse_json(llm.complete(_SYS, _prompt(goal, depth, max_depth, node_id, hint), model=model))
        ref = Refinement(data.get("refinement", "LEAF"))
        return ref, list(data.get("children") or []), data.get("technique_id")

    def _build_subtree(node_id: str, goal: str, depth: int) -> AttackTreeNode:
        # depth/loop guard: force a LEAF at the depth bound regardless of what the model proposes
        if depth >= max_depth:
            return AttackTreeNode(id=node_id, goal=goal, refinement=Refinement.LEAF)
        ref, child_goals, tid = _refine(goal, depth, node_id)
        if ref == Refinement.LEAF or not child_goals:
            if tid:
                index.enforce_resolves([tid])  # technique-ID invariant
            return AttackTreeNode(id=node_id, goal=goal, refinement=Refinement.LEAF, technique_id=tid)
        children = [
            _build_subtree(f"{node_id}.{i}", g, depth + 1) for i, g in enumerate(child_goals)
        ]
        return AttackTreeNode(id=node_id, goal=goal, refinement=ref, children=children)

    def ingest(state: D3State):
        return {
            "ref_index_version": index.version,
            "max_depth": state.get("max_depth", max_depth),
            "trace": [
                trace_entry(state["run_id"], index.version, GRAPH, "ingest", "root_goal",
                            {"goal": state["goal"]})
            ],
        }

    def expand_root(state: D3State):
        ref, child_goals, _ = _refine(state["goal"], 0, "root")
        if ref == Refinement.LEAF or not child_goals:
            root = AttackTreeNode(id="root", goal=state["goal"], refinement=Refinement.LEAF)
            return Command(update={"root": root, "subtrees": []}, goto="assemble")
        root = AttackTreeNode(id="root", goal=state["goal"], refinement=ref)
        sends = [
            Send(
                "expand_subtree",
                {"run_id": state["run_id"], "node_id": f"root.{i}", "goal": g, "depth": 1},
            )
            for i, g in enumerate(child_goals)
        ]
        return Command(
            update={
                "root": root,
                "trace": [
                    trace_entry(state["run_id"], index.version, GRAPH, "expand_root", ref.value,
                                {"children": len(child_goals)})
                ],
            },
            goto=sends,
        )

    def expand_subtree(state: D3State):
        sub = _build_subtree(state["node_id"], state["goal"], state["depth"])
        return {
            "subtrees": [sub],
            "trace": [
                trace_entry(state["run_id"], index.version, GRAPH, "expand_subtree", "built",
                            {"node_id": state["node_id"]})
            ],
        }

    def assemble(state: D3State):
        root = state["root"]
        subs = sorted(state.get("subtrees", []), key=lambda n: n.id)  # deterministic order
        return {"tree": root.model_copy(update={"children": subs})}

    def critic(state: D3State):
        wf = well_formedness_critic(state["tree"], index, state["max_depth"])
        shadow = semantic_refinement_critic(llm, state["tree"], model=critic_model)
        return {
            "wf": wf,
            "shadow": shadow,
            "trace": [
                trace_entry(state["run_id"], index.version, GRAPH, "wf_critic",
                            "pass" if wf.ok else "fail", {"violations": wf.violations}),
                trace_entry(state["run_id"], index.version, GRAPH, "semantic_critic_shadow",
                            shadow.verdict,
                            {"gating_authority": shadow.gating_authority, "notes": shadow.notes}),
            ],
        }

    def route(state: D3State):
        # ONLY the deterministic critic gates (C5); the shadow critic never blocks the run.
        return "gate" if state["wf"].ok else "incomplete"

    def incomplete(state: D3State):
        return {}

    def gate(state: D3State):
        decision = interrupt(
            {
                "summary": f"Attack tree for '{state['goal']}' — well-formedness PASSED.",
                "evidence": state["tree"].model_dump(),
                "shadow_critic": {
                    "verdict": state["shadow"].verdict,
                    "gating_authority": state["shadow"].gating_authority,
                },
                "note": "Surface evidence, not a verdict. The semantic critic is advisory "
                "(shadow mode). You dispose.",
            }
        )
        return {
            "disposition": decision or {},
            "trace": [
                trace_entry(state["run_id"], index.version, GRAPH, "gate", "disposed",
                            {"approved": bool(decision and decision.get("approved"))})
            ],
        }

    def publish(state: D3State):
        ticket = None
        if state.get("disposition", {}).get("approved"):
            ticket = approval_queue.submit(
                {"type": "attack_tree", "graph": GRAPH, "tree": state["tree"].model_dump()}
            )
        return {
            "ticket_id": ticket,
            "trace": [
                trace_entry(state["run_id"], index.version, GRAPH, "publish",
                            "submitted" if ticket else "withheld", {"ticket_id": ticket})
            ],
        }

    g = StateGraph(D3State)
    for name, fn in [
        ("ingest", ingest),
        ("expand_root", expand_root),
        ("expand_subtree", expand_subtree),
        ("assemble", assemble),
        ("critic", critic),
        ("incomplete", incomplete),
        ("gate", gate),
        ("publish", publish),
    ]:
        g.add_node(name, fn)

    g.add_edge(START, "ingest")
    g.add_edge("ingest", "expand_root")
    g.add_edge("expand_subtree", "assemble")
    g.add_edge("assemble", "critic")
    g.add_conditional_edges("critic", route, {"gate": "gate", "incomplete": "incomplete"})
    g.add_edge("gate", "publish")
    g.add_edge("incomplete", END)
    g.add_edge("publish", END)
    return g.compile(checkpointer=checkpointer)
