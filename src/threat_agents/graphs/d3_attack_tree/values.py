"""Deterministic attack-tree value propagation (Schneier).

Leaf values propagate to the root: an OR node takes the MIN child value (the cheapest way to
achieve the goal); AND/SAND take the SUM (every sub-goal is required). With a per-leaf cost this
yields "cost of the cheapest attack" at the root. Pure function, no LLM — part of the deterministic
structural layer. Leaves default to `leaf_cost` when they carry no explicit value.
"""

from __future__ import annotations

from ...common.schema import AttackTreeNode, Refinement


def propagate_cost(node: AttackTreeNode, leaf_cost: float = 1.0) -> AttackTreeNode:
    if node.refinement == Refinement.LEAF:
        v = node.value if node.value is not None else leaf_cost
        return node.model_copy(update={"value": float(v)})
    kids = [propagate_cost(c, leaf_cost) for c in node.children]
    vals = [k.value for k in kids if k.value is not None]
    if node.refinement == Refinement.OR:
        value = min(vals) if vals else 0.0  # cheapest sufficient child
    else:  # AND / SAND — every child required
        value = float(sum(vals))
    return node.model_copy(update={"children": kids, "value": value})
