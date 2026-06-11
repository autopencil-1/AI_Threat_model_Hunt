from eval.spike.corpus import SAMPLE_CORPUS, load_corpus
from eval.spike.metrics import AccuracyReport, gate_verdict, ranker_accuracy, tau_sweep
from eval.spike.ranker import LexicalRanker
from eval.spike.run_spike import run_spike
from threat_agents.common.grounding.reference_index import ReferenceIndex


# ---- metrics: pure functions ----
def test_tau_sweep_monotonic():
    pts = tau_sweep([0.9, 0.5, 0.1, 0.0], [0.05, 0.3, 0.6, 1.0])
    rates = [p.miss_rate for p in pts]
    assert rates == sorted(rates)  # miss-rate is non-decreasing in τ
    assert pts[0].miss_rate == 0.25  # only 0.0 < 0.05
    assert pts[-1].miss_rate == 1.0  # all < 1.0


def test_ranker_accuracy():
    pairs = [
        (["T1", "T2", "T3"], ["T1"]),  # rank 0
        (["T9", "T2", "T3"], ["T3"]),  # rank 2
        (["T9", "T8", "T7"], ["T1"]),  # miss
    ]
    acc = ranker_accuracy(pairs)
    assert acc.n_grounded == 3
    assert acc.top1 == round(1 / 3, 4)
    assert acc.top3 == round(2 / 3, 4)
    assert acc.mrr == round((1.0 + 1 / 3 + 0.0) / 3, 4)


def test_ranker_accuracy_empty():
    assert ranker_accuracy([]) == AccuracyReport(0, 0.0, 0.0, 0.0, 0.0)


# ---- verdict: the falsifiable rule ----
def _sweep(miss_rate_at_03):
    # craft a sweep whose τ=0.3 point has the given miss-rate
    from eval.spike.metrics import TauPoint

    return [TauPoint(0.3, miss_rate_at_03, 0, 0)]


def test_verdict_veto_on_high_miss_rate():
    v = gate_verdict(_sweep(0.7), AccuracyReport(10, 0.9, 0.95, 0.97, 0.92),
                     sane_tau=0.3, miss_rate_ceiling=0.4, top1_floor=0.6)
    assert v.decision == "veto"
    assert any("REFUTED" in r for r in v.reasons)


def test_verdict_veto_on_low_top1():
    v = gate_verdict(_sweep(0.1), AccuracyReport(10, 0.4, 0.6, 0.7, 0.5),
                     sane_tau=0.3, miss_rate_ceiling=0.4, top1_floor=0.6)
    assert v.decision == "veto"
    assert any("mis-grounding" in r for r in v.reasons)


def test_verdict_proceed():
    v = gate_verdict(_sweep(0.1), AccuracyReport(10, 0.9, 0.95, 0.97, 0.92),
                     sane_tau=0.3, miss_rate_ceiling=0.4, top1_floor=0.6)
    assert v.decision == "proceed"


# ---- baseline ranker + corpus ----
def test_lexical_ranker_ranks_by_name_overlap():
    ranker = LexicalRanker(ReferenceIndex.from_seed())
    ranked = ranker.rank("brute force credential guessing against the login", k=5)
    assert ranked, "expected at least one candidate"
    assert ranked[0][0] == "T1110"  # Brute Force
    assert 0.0 < ranked[0][1] <= 1.0


def test_sample_corpus_has_a_novel_item():
    items = load_corpus(SAMPLE_CORPUS)
    assert len(items) >= 10
    assert any(not it.ground_truth for it in items)  # exercises miss-rate


# ---- end-to-end on the sample corpus (seed index, offline/deterministic) ----
def test_run_spike_end_to_end_green_path():
    items = load_corpus(SAMPLE_CORPUS)
    report = run_spike(items, LexicalRanker(ReferenceIndex.from_seed()), "seed-test")

    assert {"index_version", "tau_sweep", "accuracy", "verdict", "per_item", "disclaimer"} <= report.keys()
    assert report["n_grounded"] >= 10
    # The sample findings carry the technique-name tokens, so the baseline should ground well...
    assert report["accuracy"]["top1"] >= 0.8
    # ...and the only no-mapping item keeps miss-rate at τ=0.3 well under the ceiling -> proceed.
    assert report["verdict"]["decision"] == "proceed"
