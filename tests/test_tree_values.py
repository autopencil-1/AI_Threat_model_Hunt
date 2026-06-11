from threat_agents.common.schema import AttackTreeNode, Refinement
from threat_agents.graphs.d3_attack_tree.values import propagate_cost


def _leaf(i, cost=None):
    return AttackTreeNode(id=i, goal=i, refinement=Refinement.LEAF, value=cost)


def test_or_takes_min():
    t = AttackTreeNode(id="r", goal="g", refinement=Refinement.OR,
                       children=[_leaf("a", 3.0), _leaf("b", 1.0), _leaf("c", 5.0)])
    assert propagate_cost(t).value == 1.0  # cheapest sufficient child


def test_and_takes_sum():
    t = AttackTreeNode(id="r", goal="g", refinement=Refinement.AND,
                       children=[_leaf("a", 3.0), _leaf("b", 1.0)])
    assert propagate_cost(t).value == 4.0  # all children required


def test_sand_takes_sum():
    t = AttackTreeNode(id="r", goal="g", refinement=Refinement.SAND,
                       children=[_leaf("a", 2.0), _leaf("b", 2.5)])
    assert propagate_cost(t).value == 4.5


def test_default_leaf_cost_and_nesting():
    t = AttackTreeNode(id="r", goal="g", refinement=Refinement.OR, children=[
        AttackTreeNode(id="x", goal="x", refinement=Refinement.AND, children=[_leaf("a"), _leaf("b")]),
        _leaf("c"),  # default cost 1.0
    ])
    out = propagate_cost(t, leaf_cost=1.0)
    # AND branch = 1+1 = 2; OR root = min(2, 1) = 1
    assert out.value == 1.0
    and_branch = next(c for c in out.children if c.id == "x")
    assert and_branch.value == 2.0
