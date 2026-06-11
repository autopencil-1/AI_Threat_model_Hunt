"""CrossEncoderRanker: logic tested with an injected scorer (no torch); real model skip-if-missing."""

import pytest

from eval.spike.ranker import CrossEncoderRanker, _sigmoid
from threat_agents.common.grounding.reference_index import ReferenceIndex


def test_sigmoid_bounds():
    assert _sigmoid(0.0) == 0.5
    assert 0.0 < _sigmoid(-10) < _sigmoid(10) < 1.0


def test_cross_encoder_orders_by_scorer_and_normalizes():
    index = ReferenceIndex.from_seed()

    # Fake frozen scorer: reward candidates whose text mentions "brute"; deterministic.
    def fake_scorer(pairs):
        return [5.0 if "brute" in cand.lower() else -5.0 for _, cand in pairs]

    ranker = CrossEncoderRanker(index, prefilter_k=50, scorer=fake_scorer)
    # query must lexically retrieve "Brute Force" into the prefilter shortlist first
    ranked = ranker.rank("brute force password guessing attack", k=5)
    assert ranked, "expected candidates from the prefilter"
    top_id, top_score = ranked[0]
    assert top_id == "T1110"  # Brute Force
    assert 0.0 < top_score < 1.0  # sigmoid-normalized
    # scores are sorted descending
    assert [s for _, s in ranked] == sorted([s for _, s in ranked], reverse=True)


def test_cross_encoder_respects_prefilter_shortlist():
    index = ReferenceIndex.from_seed()
    seen = {}

    def counting_scorer(pairs):
        seen["n"] = len(pairs)
        return [0.0] * len(pairs)

    CrossEncoderRanker(index, prefilter_k=3, scorer=counting_scorer).rank("brute force login", k=10)
    assert seen["n"] <= 3  # only the prefilter shortlist reaches the cross-encoder


def test_real_cross_encoder_if_available():
    pytest.importorskip("sentence_transformers")
    index = ReferenceIndex.from_seed()
    ranker = CrossEncoderRanker(index, prefilter_k=20)
    ranked = ranker.rank("hundreds of failed login attempts; password brute forcing", k=5)
    assert ranked
    assert all(0.0 <= s <= 1.0 for _, s in ranked)
    assert "T1110" in [tid for tid, _ in ranked]  # Brute Force should surface in the top-5
