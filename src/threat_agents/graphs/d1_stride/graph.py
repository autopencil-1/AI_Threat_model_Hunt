"""D1 — STRIDE/PASTA threat-modeling graph.

Topology: orchestrator-worker. `Send` fan-out per DFD element → bounded LLM classification of
applicable STRIDE categories → deterministic coverage critic (gates) → `interrupt()` before
publish (the only side-effecting step) → submit to the approval queue. The framework is the
control flow; the LLM only drafts threats inside the worker node.
"""

from __future__ import annotations

import operator
from typing import Annotated, Optional, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send, interrupt

from ...common.audit import trace_entry
from ...common.grounding.reference_index import ReferenceIndex
from ...common.integrations.base import ApprovalQueueAdapter
from ...common.llm import DEFAULT_MODEL, LLMClient, parse_json
from ...common.schema import DFD, DFDElement, StrideCategory, Threat, ThreatModel, TraceNode
from .critic import CoverageResult, coverage_critic
from .stride_matrix import applicable_categories

GRAPH = "D1-STRIDE"

_SYS = (
    "You are a STRIDE threat-modeling assistant. For the given DFD element, draft ONE concrete "
    "threat per applicable STRIDE category. Output STRICT JSON: a list of objects with keys "
    '"category","description","technique_ids","mitigation". "category" is one of S,T,R,I,D,E,A. '
    '"technique_ids" are MITRE ATT&CK IDs (e.g. "T1190") or []. No prose outside the JSON.'
)


class D1State(TypedDict, total=False):
    run_id: str
    ref_index_version: str
    dfd: DFD
    element: DFDElement  # per-worker payload
    threats: Annotated[list[Threat], operator.add]
    trace: Annotated[list[TraceNode], operator.add]
    coverage: CoverageResult
    disposition: dict
    ticket_id: Optional[str]
    threat_model: ThreatModel


def _worker_prompt(el: DFDElement, cats, vocab: str) -> str:
    codes = ",".join(c.value for c in sorted(cats, key=lambda c: c.value))
    return (
        f"Element name: {el.name}\nElement type: {el.type.value}\nis_ai_agent: {el.is_ai_agent}\n"
        f"Applicable STRIDE categories: {codes}\n\n"
        "Cite technique_ids ONLY from this ATT&CK list (use base IDs; [] if none apply):\n"
        f"{vocab}\n\n"
        f'[[STRIDE element_id="{el.id}" categories="{codes}"]]'
    )


def build_d1_graph(
    llm: LLMClient,
    index: ReferenceIndex,
    approval_queue: ApprovalQueueAdapter,
    checkpointer,
    model: str = DEFAULT_MODEL,
):
    vocab = index.vocabulary()

    def ingest(state: D1State):
        dfd = state["dfd"]
        return {
            "ref_index_version": index.version,
            "trace": [
                trace_entry(
                    state["run_id"], index.version, GRAPH, "ingest", "loaded_dfd",
                    {"elements": len(dfd.stride_elements())},
                )
            ],
        }

    def fan_out(state: D1State):
        return [
            Send("analyze_element", {"run_id": state["run_id"], "element": el})
            for el in state["dfd"].stride_elements()
        ]

    def analyze_element(state: D1State):
        el = state["element"]
        cats = applicable_categories(el)
        items = parse_json(llm.complete(_SYS, _worker_prompt(el, cats, vocab), model=model))
        threats: list[Threat] = []
        all_ids: list[str] = []
        for it in items:
            try:
                cat = StrideCategory(it["category"])
            except (ValueError, KeyError):
                continue
            if cat not in cats:
                continue  # discard out-of-scope categories (framework constrains the LLM)
            tids = list(it.get("technique_ids") or [])
            all_ids += tids
            threats.append(
                Threat(
                    id=f"{el.id}:{cat.value}",
                    element_id=el.id,
                    category=cat,
                    description=it.get("description", ""),
                    technique_ids=tids,
                    mitigation=it.get("mitigation"),
                )
            )
        index.enforce_resolves(all_ids)  # technique-ID invariant — hard fail on unresolved
        return {
            "threats": threats,
            "trace": [
                trace_entry(
                    state["run_id"], index.version, GRAPH, "analyze_element", "drafted",
                    {"element_id": el.id, "threats": len(threats)},
                )
            ],
        }

    def critic(state: D1State):
        cov = coverage_critic(state["dfd"], state["threats"])
        return {
            "coverage": cov,
            "trace": [
                trace_entry(
                    state["run_id"], index.version, GRAPH, "coverage_critic",
                    "pass" if cov.ok else "fail",
                    {"gaps": [[e, c.value] for e, c in cov.gaps]},
                )
            ],
        }

    def route_after_critic(state: D1State):
        return "gate" if state["coverage"].ok else "incomplete"

    def incomplete(state: D1State):
        cov = state["coverage"]
        tm = ThreatModel(
            dfd_name=state["dfd"].name,
            threats=state["threats"],
            coverage_ok=False,
            gaps=[(e, c.value) for e, c in cov.gaps],
        )
        return {"threat_model": tm}

    def gate(state: D1State):
        decision = interrupt(
            {
                "summary": f"STRIDE threat model for '{state['dfd'].name}' — "
                f"{len(state['threats'])} threats, coverage OK.",
                "evidence": [t.model_dump() for t in state["threats"]],
                "note": "Surface evidence, not a verdict. You (the analyst) are the disposer. "
                "Approve to publish.",
            }
        )
        return {
            "disposition": decision or {},
            "trace": [
                trace_entry(
                    state["run_id"], index.version, GRAPH, "gate", "disposed",
                    {"approved": bool(decision and decision.get("approved"))},
                )
            ],
        }

    def publish(state: D1State):
        tm = ThreatModel(
            dfd_name=state["dfd"].name, threats=state["threats"], coverage_ok=True, gaps=[]
        )
        ticket = None
        if state.get("disposition", {}).get("approved"):
            ticket = approval_queue.submit(
                {"type": "threat_model", "graph": GRAPH, "model": tm.model_dump()}
            )
        return {
            "threat_model": tm,
            "ticket_id": ticket,
            "trace": [
                trace_entry(
                    state["run_id"], index.version, GRAPH, "publish",
                    "submitted" if ticket else "withheld", {"ticket_id": ticket},
                )
            ],
        }

    g = StateGraph(D1State)
    g.add_node("ingest", ingest)
    g.add_node("analyze_element", analyze_element)
    g.add_node("critic", critic)
    g.add_node("incomplete", incomplete)
    g.add_node("gate", gate)
    g.add_node("publish", publish)

    g.add_edge(START, "ingest")
    g.add_conditional_edges("ingest", fan_out, ["analyze_element"])
    g.add_edge("analyze_element", "critic")
    g.add_conditional_edges("critic", route_after_critic, {"gate": "gate", "incomplete": "incomplete"})
    g.add_edge("gate", "publish")
    g.add_edge("incomplete", END)
    g.add_edge("publish", END)
    return g.compile(checkpointer=checkpointer)
