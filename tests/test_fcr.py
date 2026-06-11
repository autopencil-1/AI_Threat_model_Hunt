from eval.fcr.metrics import false_confirmation_rate, false_rejection_rate, score
from eval.fcr.mutations import good_trees, labeled_cases, mutate
from eval.fcr.run_fcr import run_fcr, semantic_critic_fn
from threat_agents.common.testing import stub_tree_llm
from threat_agents.graphs.d3_attack_tree.critic import ShadowResult


def test_mutate_produces_valid_and_invalid():
    cases = mutate(good_trees()[0])
    assert sum(c.expected_valid for c in cases) == 1
    assert sum(not c.expected_valid for c in cases) >= 2


def test_metrics_on_handcrafted_results():
    cases = labeled_cases()
    # pretend the critic confirmed EVERYTHING (verdict pass for all)
    all_confirmed = [(c, True) for c in cases]
    assert false_confirmation_rate(all_confirmed) == 1.0  # every invalid confirmed
    assert false_rejection_rate(all_confirmed) == 0.0  # no valid rejected

    # a perfect critic: confirm valid, reject invalid
    perfect = [(c, c.expected_valid) for c in cases]
    assert false_confirmation_rate(perfect) == 0.0
    assert false_rejection_rate(perfect) == 0.0


def test_stub_critic_has_high_fcr_and_does_not_clear_gate():
    # The stub semantic critic always returns "pass" -> it confirms invalid trees -> FCR 1.0.
    report = run_fcr(labeled_cases(), semantic_critic_fn(stub_tree_llm()), fcr_ceiling=0.1)
    assert report.fcr == 1.0
    assert report.clears_gate is False


def test_perfect_oracle_clears_gate():
    def oracle(tree):
        bad_goals = {"Bake a chocolate cake", "Water the office plants"}
        child_goals = [c.goal for c in tree.children]
        invalid = any(g in bad_goals for g in child_goals) or any(g == tree.goal for g in child_goals)
        return ShadowResult(verdict="fail" if invalid else "pass", gating_authority=False)

    report = run_fcr(labeled_cases(), oracle, fcr_ceiling=0.1)
    assert report.fcr == 0.0
    assert report.frr == 0.0
    assert report.clears_gate is True


def test_score_ceiling_boundary():
    cases = labeled_cases()
    # one invalid confirmed out of all invalid
    results = []
    confirmed_one = False
    for c in cases:
        if not c.expected_valid and not confirmed_one:
            results.append((c, True))
            confirmed_one = True
        else:
            results.append((c, c.expected_valid))
    rep = score(results, fcr_ceiling=0.5)
    assert 0.0 < rep.fcr <= 0.5
    assert rep.clears_gate is True
