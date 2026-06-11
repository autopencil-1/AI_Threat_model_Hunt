"""D3 — Recursive AND/OR attack-tree graph.

Topology: recursive orchestrator-worker with **true per-node `Send` fan-out**. A `frontier` router
fans out one `expand_node` worker per unexpanded node at the current depth; each worker refines its
node (bounded LLM) and appends its children to the frontier; the router loops until the frontier
drains or the depth bound is hit, then assembles the tree. Each level is a clean LangGraph
superstep barrier — no in-worker recursion, no race on assembly.

Then: deterministic well-formedness critic (gates) + leaf-value propagation (Schneier cost) +
semantic refinement critic in SHADOW mode (no gating authority, 05 §2.4 / C5). `interrupt()` before
publish. Untrusted goal/context passes the one ingestion boundary first.
"""

from __future__ import annotations

import operator
from typing import Annotated, Optional, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send, interrupt

from ...common.audit import trace_entry
from ...common.grounding.reference_index import ReferenceIndex
from ...common.injection_boundary import IngestionBoundary
from ...common.integrations.base import ApprovalQueueAdapter
from ...common.llm import CRITIC_MODEL, DEFAULT_MODEL, LLMClient, parse_json
from ...common.schema import (
    AttackTreeNode,
    ConfidenceRecord,
    CriticVerdict,
    Provenance,
    Refinement,
    TraceNode,
)
from .critic import (
    ShadowResult,
    WellFormednessResult,
    semantic_refinement_critic,
    well_formedness_critic,
)
from .values import propagate_cost

GRAPH = "D3-ATTACK-TREE"

_SYS = (
    "You are an attack-tree analyst (Schneier AND/OR refinement). Refine the given goal into its "
    "next level. Output STRICT JSON with keys "
    '"refinement","children","technique_id". "refinement" is one of AND|OR|SAND|LEAF; "children" '
    'is a list of sub-goal strings (empty for LEAF); "technique_id" is a MITRE ATT&CK ID for a '
    "LEAF or null. No prose outside the JSON."
)


def _merge_nodes(a: dict | None, b: dict | None) -> dict:
    out = dict(a or {})
    out.update(b or {})
    return out


class D3State(TypedDict, total=False):
    run_id: str
    ref_index_version: str
    goal: str
    context: Optional[str]
    max_depth: int
    specs: Annotated[list[dict], operator.add]  # discovered node specs {id, goal, depth}
    nodes: Annotated[dict, _merge_nodes]  # id -> expanded record
    spec: dict  # per-worker payload
    tree: AttackTreeNode
    wf: WellFormednessResult
    shadow: ShadowResult
    confidence: ConfidenceRecord
    trace: Annotated[list[TraceNode], operator.add]
    disposition: dict
    ticket_id: Optional[str]


def _prompt(goal: str, depth: int, max_depth: int, node_id: str, hint: str, context: str) -> str:
    ctx = f"Context (sanitized, untrusted):\n{context}\n\n" if context else ""
    return (
        f"{ctx}Goal: {goal}\nCurrent depth: {depth}\nMax depth: {max_depth}\n\n"
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
    boundary: IngestionBoundary | None = None,
):
    hint = index.grounding_hint()
    boundary = boundary or IngestionBoundary()

    def _refine(goal: str, depth: int, node_id: str, context: str):
        data = parse_json(
            llm.complete(_SYS, _prompt(goal, depth, max_depth, node_id, hint, context), model=model)
        )
        ref = Refinement(data.get("refinement", "LEAF"))
        return ref, list(data.get("children") or []), data.get("technique_id")

    def ingest(state: D3State):
        # Untrusted goal/context through the one ingestion boundary (05 §2.2).
        goal = boundary.sanitize(state["goal"]).text
        ctx = boundary.sanitize(state["context"]).text if state.get("context") else ""
        return {
            "ref_index_version": index.version,
            "max_depth": state.get("max_depth", max_depth),
            "goal": goal,
            "context": ctx,
            "specs": [{"id": "root", "goal": goal, "depth": 0}],
            "nodes": {},
            "trace": [
                trace_entry(state["run_id"], index.version, GRAPH, "ingest", "sanitized_root_goal",
                            {"goal": goal})
            ],
        }

    def expand_router(state: D3State):
        nodes = state.get("nodes", {})
        md = state.get("max_depth", max_depth)
        pending = [s for s in state.get("specs", []) if s["id"] not in nodes and s["depth"] < md]
        if pending:
            return [Send("expand_node", {"run_id": state["run_id"], "spec": s}) for s in pending]
        return "assemble"

    def frontier(state: D3State):
        return {}  # passthrough; routing is on the conditional edge

    def expand_node(state: D3State):
        spec = state["spec"]
        nid, goal, depth = spec["id"], spec["goal"], spec["depth"]
        ref, child_goals, tid = _refine(goal, depth, nid, state.get("context", ""))
        if ref == Refinement.LEAF or not child_goals:
            if tid:
                index.enforce_resolves([tid])  # technique-ID invariant
            record = {"id": nid, "goal": goal, "depth": depth, "refinement": "LEAF",
                      "technique_id": tid, "child_ids": []}
            return {
                "nodes": {nid: record},
                "trace": [trace_entry(state["run_id"], index.version, GRAPH, "expand_node",
                                      "leaf", {"node_id": nid})],
            }
        child_specs = [
            {"id": f"{nid}.{i}", "goal": g, "depth": depth + 1} for i, g in enumerate(child_goals)
        ]
        record = {"id": nid, "goal": goal, "depth": depth, "refinement": ref.value,
                  "technique_id": None, "child_ids": [c["id"] for c in child_specs]}
        return {
            "nodes": {nid: record},
            "specs": child_specs,
            "trace": [trace_entry(state["run_id"], index.version, GRAPH, "expand_node",
                                  ref.value, {"node_id": nid, "children": len(child_specs)})],
        }

    def assemble(state: D3State):
        nodes = state.get("nodes", {})
        specs_by_id = {s["id"]: s for s in state.get("specs", [])}

        def build(nid: str) -> AttackTreeNode:
            rec = nodes.get(nid)
            if rec is None:  # spec hit the depth bound and was never expanded -> forced leaf
                spec = specs_by_id.get(nid, {"goal": ""})
                return AttackTreeNode(id=nid, goal=spec.get("goal", ""), refinement=Refinement.LEAF)
            ref = Refinement(rec["refinement"])
            if ref == Refinement.LEAF:
                return AttackTreeNode(id=nid, goal=rec["goal"], refinement=Refinement.LEAF,
                                      technique_id=rec.get("technique_id"))
            children = [build(cid) for cid in rec.get("child_ids", [])]
            return AttackTreeNode(id=nid, goal=rec["goal"], refinement=ref, children=children)

        tree = propagate_cost(build("root"))  # sets .value bottom-up
        return {"tree": tree}

    def critic(state: D3State):
        wf = well_formedness_critic(state["tree"], index, state["max_depth"])
        shadow = semantic_refinement_critic(llm, state["tree"], model=critic_model)

        leaves = _leaves(state["tree"])
        grounded = sum(1 for leaf_node in leaves if leaf_node.technique_id)
        confidence = ConfidenceRecord(
            retrieval_relevance=(grounded / len(leaves)) if leaves else 0.0,
            critic_verdict=CriticVerdict.PASS if wf.ok else CriticVerdict.FAIL,
            provenance=Provenance.BASE,
        )
        return {
            "wf": wf,
            "shadow": shadow,
            "confidence": confidence,
            "trace": [
                trace_entry(state["run_id"], index.version, GRAPH, "wf_critic",
                            "pass" if wf.ok else "fail", {"violations": wf.violations}),
                trace_entry(state["run_id"], index.version, GRAPH, "semantic_critic_shadow",
                            shadow.verdict,
                            {"gating_authority": shadow.gating_authority, "notes": shadow.notes}),
            ],
        }

    def route_after_critic(state: D3State):
        # ONLY the deterministic critic gates (C5); the shadow critic never blocks the run.
        return "gate" if state["wf"].ok else "incomplete"

    def incomplete(state: D3State):
        return {}

    def gate(state: D3State):
        decision = interrupt(
            {
                "summary": f"Attack tree for '{state['goal']}' — well-formedness PASSED "
                f"(root cost={state['tree'].value}).",
                "evidence": state["tree"].model_dump(),
                "confidence": state["confidence"].model_dump(),
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
            "trace": [trace_entry(state["run_id"], index.version, GRAPH, "gate", "disposed",
                                  {"approved": bool(decision and decision.get("approved"))})],
        }

    def publish(state: D3State):
        ticket = None
        if state.get("disposition", {}).get("approved"):
            ticket = approval_queue.submit(
                {"type": "attack_tree", "graph": GRAPH, "tree": state["tree"].model_dump(),
                 "confidence": state["confidence"].model_dump()}
            )
        return {
            "ticket_id": ticket,
            "trace": [trace_entry(state["run_id"], index.version, GRAPH, "publish",
                                  "submitted" if ticket else "withheld", {"ticket_id": ticket})],
        }

    g = StateGraph(D3State)
    for name, fn in [
        ("ingest", ingest),
        ("frontier", frontier),
        ("expand_node", expand_node),
        ("assemble", assemble),
        ("critic", critic),
        ("incomplete", incomplete),
        ("gate", gate),
        ("publish", publish),
    ]:
        g.add_node(name, fn)

    g.add_edge(START, "ingest")
    g.add_edge("ingest", "frontier")
    g.add_conditional_edges("frontier", expand_router, ["expand_node", "assemble"])
    g.add_edge("expand_node", "frontier")  # loop back: re-evaluate the frontier each level
    g.add_edge("assemble", "critic")
    g.add_conditional_edges("critic", route_after_critic, {"gate": "gate", "incomplete": "incomplete"})
    g.add_edge("gate", "publish")
    g.add_edge("incomplete", END)
    g.add_edge("publish", END)
    return g.compile(checkpointer=checkpointer)


def _leaves(node: AttackTreeNode) -> list[AttackTreeNode]:
    if node.refinement == Refinement.LEAF:
        return [node]
    out: list[AttackTreeNode] = []
    for c in node.children:
        out.extend(_leaves(c))
    return out
