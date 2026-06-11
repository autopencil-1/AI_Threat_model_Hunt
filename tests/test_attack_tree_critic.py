import pytest

from threat_agents.common.grounding.reference_index import ReferenceIndex
from threat_agents.common.schema import AttackTreeNode, Refinement
from threat_agents.graphs.d3_attack_tree.critic import (
    SEMANTIC_CRITIC_HAS_GATING_AUTHORITY,
    semantic_refinement_critic,
    well_formedness_critic,
)


@pytest.fixture
def index():
    return ReferenceIndex.from_seed()


def _good_tree() -> AttackTreeNode:
    return AttackTreeNode(
        id="root", goal="g", refinement=Refinement.OR,
        children=[
            AttackTreeNode(id="root.0", goal="a", refinement=Refinement.LEAF, technique_id="T1190"),
            AttackTreeNode(id="root.1", goal="b", refinement=Refinement.LEAF, technique_id="T1078"),
        ],
    )


def test_wellformed_tree_passes(index):
    assert well_formedness_critic(_good_tree(), index, max_depth=3).ok


def test_leaf_with_children_fails(index):
    t = AttackTreeNode(id="root", goal="g", refinement=Refinement.LEAF,
                       children=[AttackTreeNode(id="c", goal="c", refinement=Refinement.LEAF)])
    res = well_formedness_critic(t, index, max_depth=3)
    assert not res.ok
    assert any("not atomic" in v for v in res.violations)


def test_unresolved_technique_fails(index):
    t = AttackTreeNode(id="root", goal="g", refinement=Refinement.OR,
                       children=[AttackTreeNode(id="root.0", goal="a", refinement=Refinement.LEAF, technique_id="T9999")])
    res = well_formedness_critic(t, index, max_depth=3)
    assert not res.ok
    assert any("unresolved" in v for v in res.violations)


def test_and_node_needs_two_children(index):
    t = AttackTreeNode(id="root", goal="g", refinement=Refinement.AND,
                       children=[AttackTreeNode(id="root.0", goal="a", refinement=Refinement.LEAF)])
    res = well_formedness_critic(t, index, max_depth=3)
    assert not res.ok
    assert any(">=2 children" in v for v in res.violations)


def test_depth_bound_violation(index):
    deep = AttackTreeNode(id="root", goal="g", refinement=Refinement.OR, children=[
        AttackTreeNode(id="root.0", goal="a", refinement=Refinement.OR, children=[
            AttackTreeNode(id="root.0.0", goal="b", refinement=Refinement.LEAF),
        ]),
    ])
    res = well_formedness_critic(deep, index, max_depth=1)
    assert not res.ok
    assert any("exceeds max_depth" in v for v in res.violations)


def test_duplicate_id_flagged(index):
    t = AttackTreeNode(id="root", goal="g", refinement=Refinement.OR, children=[
        AttackTreeNode(id="dup", goal="a", refinement=Refinement.LEAF),
        AttackTreeNode(id="dup", goal="b", refinement=Refinement.LEAF),
    ])
    res = well_formedness_critic(t, index, max_depth=3)
    assert not res.ok
    assert any("duplicate" in v for v in res.violations)


def test_semantic_critic_is_shadow_only():
    # Even when the critic returns a verdict, it must carry no gating authority in Stage 1.
    from threat_agents.common.testing import stub_tree_llm

    res = semantic_refinement_critic(stub_tree_llm(), _good_tree())
    assert res.gating_authority is False
    assert SEMANTIC_CRITIC_HAS_GATING_AUTHORITY is False
