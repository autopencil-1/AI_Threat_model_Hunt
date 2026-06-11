"""Deterministic offline test doubles (shipped so both tests and examples can import them).

The responders parse a machine-readable marker the graph appends to each worker prompt and
emit valid JSON matching the production contract. A real `AnthropicLLM` ignores the marker
as context and answers from the instructions; the stub answers from the marker. This is how
the whole graph — fan-out, critics, gate — runs end-to-end with no API key.
"""

from __future__ import annotations

import json
import re

from .llm import StubLLM

_STRIDE = re.compile(r'\[\[STRIDE element_id="([^"]*)" categories="([^"]*)"\]\]')
_TREE = re.compile(r'\[\[TREE id="([^"]*)" depth="(\d+)" max_depth="(\d+)" goal="([^"]*)"\]\]')
_JUDGE = re.compile(r"\[\[JUDGE\]\]")

_SEED_TIDS = ["T1190", "T1078", "T1059", "T1110"]


def stride_responder(system: str, user: str) -> str:
    """One drafted threat per applicable STRIDE category (so the coverage critic passes)."""
    m = _STRIDE.search(user)
    eid, cats = (m.group(1), m.group(2).split(",")) if m else ("?", [])
    out = []
    for i, c in enumerate(cats):
        out.append(
            {
                "category": c,
                "description": f"{c}-class threat against {eid}",
                "technique_ids": (["T1190"] if i == 0 else []),
                "mitigation": "apply appropriate control",
            }
        )
    return json.dumps(out)


def tree_responder(system: str, user: str) -> str:
    """OR-refine until depth 2, then emit resolving LEAF techniques. Also answers the shadow judge."""
    if _JUDGE.search(user):
        return json.dumps({"verdict": "pass", "notes": ["refinement plausible (shadow / advisory)"]})
    m = _TREE.search(user)
    nid, depth, maxd, goal = (
        (m.group(1), int(m.group(2)), int(m.group(3)), m.group(4)) if m else ("n", 0, 3, "goal")
    )
    if depth >= 2:
        tid = _SEED_TIDS[(len(goal) + depth) % len(_SEED_TIDS)]
        return json.dumps({"refinement": "LEAF", "children": [], "technique_id": tid})
    return json.dumps(
        {
            "refinement": "OR",
            "children": [f"{goal} via vector A", f"{goal} via vector B"],
            "technique_id": None,
        }
    )


def stub_stride_llm() -> StubLLM:
    return StubLLM(stride_responder)


def stub_tree_llm() -> StubLLM:
    return StubLLM(tree_responder)
