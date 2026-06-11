"""Spike metrics (pure functions) + the falsifiable gate verdict.

- `tau_sweep`: miss-rate vs τ, where a "miss" is max ranker score < τ (05 §2.3 / C3).
- `ranker_accuracy`: top-1/3/5 + MRR of the ground-truth technique (B5) — measures whether an ID
  resolves to the *correct* technique, not just *some* object.
- `gate_verdict`: the pre-stated falsifiable rule — high miss-rate OR low top-1 VETOES the tiered
  dispatcher design (05 §A.2). Thresholds here are PLACEHOLDERS; real ones are set by the
  floor-tuning owner after calibration (05 §2.6 / C4).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TauPoint:
    tau: float
    miss_rate: float
    n_miss: int
    n_total: int


def tau_sweep(max_scores: list[float], taus: list[float]) -> list[TauPoint]:
    n = len(max_scores)
    out: list[TauPoint] = []
    for tau in taus:
        n_miss = sum(1 for s in max_scores if s < tau)
        out.append(TauPoint(round(tau, 4), (n_miss / n if n else 0.0), n_miss, n))
    return out


@dataclass
class AccuracyReport:
    n_grounded: int
    top1: float
    top3: float
    top5: float
    mrr: float


def _rank_of_truth(ranked_ids: list[str], ground_truth: list[str]) -> int | None:
    gt = set(ground_truth)
    for i, tid in enumerate(ranked_ids):
        if tid in gt:
            return i
    return None


def ranker_accuracy(pairs: list[tuple[list[str], list[str]]]) -> AccuracyReport:
    """`pairs` = (ranked_ids, ground_truth_ids) for GROUNDED items only (non-empty ground truth)."""
    n = len(pairs)
    if n == 0:
        return AccuracyReport(0, 0.0, 0.0, 0.0, 0.0)
    ranks = [_rank_of_truth(r, gt) for r, gt in pairs]

    def topk(k: int) -> float:
        return sum(1 for r in ranks if r is not None and r < k) / n

    mrr = sum((1.0 / (r + 1)) if r is not None else 0.0 for r in ranks) / n
    return AccuracyReport(n, round(topk(1), 4), round(topk(3), 4), round(topk(5), 4), round(mrr, 4))


@dataclass
class Verdict:
    decision: str  # "proceed" | "veto"
    reasons: list[str]


def gate_verdict(
    sweep: list[TauPoint],
    accuracy: AccuracyReport,
    *,
    sane_tau: float,
    miss_rate_ceiling: float,
    top1_floor: float,
) -> Verdict:
    reasons: list[str] = []
    veto = False

    point = min(sweep, key=lambda p: abs(p.tau - sane_tau)) if sweep else None
    if point and point.miss_rate > miss_rate_ceiling:
        veto = True
        reasons.append(
            f"miss-rate {point.miss_rate:.2f} at tau~{point.tau} exceeds ceiling {miss_rate_ceiling} "
            "-> tiered KG-first design REFUTED; a reasoner-first (Position-B) design was right (C3)."
        )
    if accuracy.n_grounded and accuracy.top1 < top1_floor:
        veto = True
        reasons.append(
            f"re-ranker top-1 {accuracy.top1:.2f} below floor {top1_floor} -> mis-grounding dominates; "
            "the off-graph detector buys little (B5). Redesign before building the dispatcher."
        )
    if not veto:
        reasons.append(
            "tiered shape supported at the chosen tau AND re-ranker top-1 clears the floor -> proceed "
            "to Stage 2 (still instrument-first / earn it; this is necessary, not sufficient)."
        )
    return Verdict("veto" if veto else "proceed", reasons)
