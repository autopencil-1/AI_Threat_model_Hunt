"""D3 critics — split per the §2.4 reading (decided in IMPLEMENTATION_STRATEGY.md §4).

1. `well_formedness_critic` — DETERMINISTIC structural. No LLM. Gates from day one.
2. `semantic_refinement_critic` — SEMANTIC. SHADOW MODE: runs with NO gating authority until
   its false-confirmation rate clears the release gate (05 §2.4 / C5). Independence lever: a
   different model (CRITIC_MODEL). Its output is logged for measurement, never to block.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ...common.grounding.reference_index import ReferenceIndex
from ...common.llm import parse_json
from ...common.schema import AttackTreeNode, Refinement

# Release gate (C5): flip to True only after the shadow false-confirmation rate clears its bound.
SEMANTIC_CRITIC_HAS_GATING_AUTHORITY = False


@dataclass
class WellFormednessResult:
    ok: bool
    violations: list[str] = field(default_factory=list)


def well_formedness_critic(
    root: AttackTreeNode, index: ReferenceIndex, max_depth: int
) -> WellFormednessResult:
    violations: list[str] = []
    seen: set[str] = set()

    def walk(n: AttackTreeNode, depth: int) -> None:
        if n.id in seen:
            violations.append(f"duplicate/cyclic node id {n.id!r}")
            return
        seen.add(n.id)
        if depth > max_depth:
            violations.append(f"node {n.id!r} exceeds max_depth {max_depth}")
        if n.refinement == Refinement.LEAF:
            if n.children:
                violations.append(f"leaf {n.id!r} has children (not atomic)")
            if n.technique_id is not None and n.technique_id not in index:
                violations.append(
                    f"leaf {n.id!r} technique {n.technique_id!r} unresolved in {index.version}"
                )
        else:
            if not n.children:
                violations.append(f"{n.refinement.value} node {n.id!r} has no children")
            if n.refinement in (Refinement.AND, Refinement.SAND) and len(n.children) < 2:
                violations.append(f"{n.refinement.value} node {n.id!r} needs >=2 children")
            for c in n.children:
                walk(c, depth + 1)

    walk(root, 0)
    return WellFormednessResult(ok=not violations, violations=violations)


@dataclass
class ShadowResult:
    verdict: str  # pass | fail | abstain — ADVISORY ONLY
    gating_authority: bool
    notes: list[str] = field(default_factory=list)


_JUDGE_SYS = (
    "You are an INDEPENDENT attack-tree critic (a different model from the author). Judge whether "
    "each refinement is valid and reasonably complete. Output STRICT JSON "
    '{"verdict":"pass|fail|abstain","notes":[...]}. No prose outside the JSON.'
)


def _flatten(n: AttackTreeNode, acc: list[str]) -> list[str]:
    acc.append(f"{n.id}:{n.refinement.value}:{n.goal}")
    for c in n.children:
        _flatten(c, acc)
    return acc


def _judge_prompt(root: AttackTreeNode) -> str:
    return "Nodes:\n" + "\n".join(_flatten(root, [])) + "\n\n[[JUDGE]]"


def semantic_refinement_critic(llm, root: AttackTreeNode, model=None) -> ShadowResult:
    try:
        data = parse_json(llm.complete(_JUDGE_SYS, _judge_prompt(root), model=model))
        verdict = data.get("verdict", "abstain")
        notes = list(data.get("notes", []))
    except Exception as ex:  # shadow mode never fails the run
        verdict, notes = "abstain", [f"shadow-error: {ex}"]
    return ShadowResult(
        verdict=verdict, gating_authority=SEMANTIC_CRITIC_HAS_GATING_AUTHORITY, notes=notes
    )
