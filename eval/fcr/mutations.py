"""Labeled-case generator for the FCR harness.

A known-good (valid) tree plus DETERMINISTIC semantic mutations that make a refinement *invalid*
while keeping it structurally well-formed (so the deterministic critic still passes — we're probing
the SEMANTIC critic). Mutations target what the semantic critic actually judges: whether children
decompose their parent goal.
"""

from __future__ import annotations

from dataclasses import dataclass

from threat_agents.common.schema import AttackTreeNode, Refinement


@dataclass
class LabeledCase:
    id: str
    tree: AttackTreeNode
    expected_valid: bool
    mutation: str


def _leaf(nid: str, goal: str, technique_id: str | None = None) -> AttackTreeNode:
    return AttackTreeNode(id=nid, goal=goal, refinement=Refinement.LEAF, technique_id=technique_id)


def good_trees() -> list[AttackTreeNode]:
    """A few hand-built, coherent, well-formed trees (the 'valid' baselines)."""
    return [
        AttackTreeNode(
            id="g1", goal="Gain unauthorized access to the auth service", refinement=Refinement.OR,
            children=[
                _leaf("g1.0", "Brute-force or credential-stuff the login endpoint", "T1110"),
                _leaf("g1.1", "Use stolen valid account credentials", "T1078"),
                _leaf("g1.2", "Steal a web session cookie to bypass MFA", "T1539"),
            ],
        ),
        AttackTreeNode(
            id="g2", goal="Exfiltrate the customer database", refinement=Refinement.OR,
            children=[
                _leaf("g2.0", "Exploit the public-facing application to reach the DB", "T1190"),
                _leaf("g2.1", "Dump credentials then read the data store", "T1003"),
            ],
        ),
    ]


def mutate(base: AttackTreeNode) -> list[LabeledCase]:
    """Return the valid baseline + deterministic invalid variants."""
    cases = [LabeledCase(f"{base.id}:identity", base, True, "identity")]

    # incoherent_children: children that do not decompose the parent goal at all
    incoherent = base.model_copy(
        update={
            "children": [
                _leaf(f"{base.id}.x0", "Bake a chocolate cake"),
                _leaf(f"{base.id}.x1", "Water the office plants"),
            ]
        }
    )
    cases.append(LabeledCase(f"{base.id}:incoherent", incoherent, False, "incoherent_children"))

    # circular_goal: a child restates the parent goal verbatim (no real refinement)
    if base.children:
        kids = [c.model_copy() for c in base.children]
        kids[0] = kids[0].model_copy(update={"goal": base.goal})
        circular = base.model_copy(update={"children": kids})
        cases.append(LabeledCase(f"{base.id}:circular", circular, False, "circular_goal"))

    return cases


def labeled_cases() -> list[LabeledCase]:
    return [c for base in good_trees() for c in mutate(base)]
