"""Decision-gate spike runner (05 §A.2).

    python eval/spike/run_spike.py                 # sample corpus, full ATT&CK if present
    python eval/spike/run_spike.py --seed          # force the seed index (offline/deterministic)
    python eval/spike/run_spike.py --corpus eval/corpora/incidents.jsonl --out report.json

Computes the miss-rate τ-sweep + re-ranker accuracy and prints the FALSIFIABLE verdict. The
baseline ranker + synthetic corpus make this a runnable framework, NOT a decision-grade result —
swap in the real frozen re-ranker over the KG frontier and a historical corpus to actually gate.
"""

from __future__ import annotations

import dataclasses
import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

import argparse  # noqa: E402
import json  # noqa: E402

from eval.spike.corpus import SAMPLE_CORPUS, CorpusItem, load_corpus  # noqa: E402
from eval.spike.metrics import gate_verdict, ranker_accuracy, tau_sweep  # noqa: E402
from eval.spike.ranker import CrossEncoderRanker, LexicalRanker, Ranker  # noqa: E402
from threat_agents.common.grounding.reference_index import ReferenceIndex  # noqa: E402

DEFAULT_TAUS = [round(0.1 * i, 2) for i in range(1, 10)]  # 0.1 .. 0.9

DISCLAIMER = (
    "NOT a decision-grade result yet. The ranker runs over a lexical prefilter (a stand-in for the "
    "Stage-2 KG-frontier traversal) on a SYNTHETIC corpus, and τ is UNCALIBRATED — score scales "
    "differ per ranker, so a fixed τ is not comparable across backends (C4). Make it decision-grade "
    "with: a historical corpus (known outcomes), the KG-frontier prefilter, and τ calibrated per "
    "ranker against a held-out set (reliability diagram) before it gates anything (05 §A.2 / C4)."
)


def run_spike(
    items: list[CorpusItem],
    ranker: Ranker,
    index_version: str,
    *,
    k: int = 10,
    taus: list[float] | None = None,
    sane_tau: float = 0.3,
    miss_rate_ceiling: float = 0.4,
    top1_floor: float = 0.6,
) -> dict:
    taus = taus or DEFAULT_TAUS
    max_scores: list[float] = []
    pairs: list[tuple[list[str], list[str]]] = []
    per_item: list[dict] = []

    for it in items:
        ranked = ranker.rank(it.finding, k=k)
        ranked_ids = [tid for tid, _ in ranked]
        max_score = ranked[0][1] if ranked else 0.0
        max_scores.append(max_score)
        if it.ground_truth:
            pairs.append((ranked_ids, it.ground_truth))
        per_item.append(
            {
                "id": it.id,
                "max_score": round(max_score, 4),
                "top3": ranked_ids[:3],
                "ground_truth": it.ground_truth,
                "hit_rank": next((i for i, t in enumerate(ranked_ids) if t in set(it.ground_truth)), None)
                if it.ground_truth
                else None,
            }
        )

    sweep = tau_sweep(max_scores, taus)
    acc = ranker_accuracy(pairs)
    verdict = gate_verdict(
        sweep, acc, sane_tau=sane_tau, miss_rate_ceiling=miss_rate_ceiling, top1_floor=top1_floor
    )

    return {
        "index_version": index_version,
        "ranker": ranker.__class__.__name__,
        "n_items": len(items),
        "n_grounded": acc.n_grounded,
        "tau_sweep": [dataclasses.asdict(p) for p in sweep],
        "accuracy": dataclasses.asdict(acc),
        "verdict": {
            "decision": verdict.decision,
            "reasons": verdict.reasons,
            "sane_tau": sane_tau,
            "miss_rate_ceiling": miss_rate_ceiling,
            "top1_floor": top1_floor,
        },
        "per_item": per_item,
        "disclaimer": DISCLAIMER,
    }


def _print_report(r: dict) -> None:
    print("=" * 78)
    print("DECISION-GATE SPIKE (05 §A.2) — measure before building the substrate/dispatcher")
    print("=" * 78)
    print(f"index : {r['index_version']}")
    print(f"ranker: {r['ranker']}")
    print(f"corpus: {r['n_items']} items ({r['n_grounded']} grounded)\n")

    print("Test A — miss-rate τ-sweep (miss = max ranker score < τ):")
    print("  τ      miss_rate   (n_miss/n)")
    for p in r["tau_sweep"]:
        print(f"  {p['tau']:<5}  {p['miss_rate']:<10.3f} ({p['n_miss']}/{p['n_total']})")
    a = r["accuracy"]
    print("\nTest B — re-ranker accuracy (does it resolve to the CORRECT technique):")
    print(f"  top1={a['top1']:.3f}  top3={a['top3']:.3f}  top5={a['top5']:.3f}  mrr={a['mrr']:.3f}")

    v = r["verdict"]
    print("\nFALSIFIABLE PREDICTION: high miss-rate at sane τ, OR low top-1, refutes the tiered design.")
    print(f"VERDICT: {v['decision'].upper()}  "
          f"(sane_tau={v['sane_tau']}, miss_ceiling={v['miss_rate_ceiling']}, top1_floor={v['top1_floor']})")
    for reason in v["reasons"]:
        print(f"  - {reason}")
    print(f"\n{r['disclaimer']}")
    print("=" * 78)


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the offline decision-gate spike.")
    ap.add_argument("--corpus", default=str(SAMPLE_CORPUS))
    ap.add_argument("--seed", action="store_true", help="force the seed index (offline/deterministic)")
    ap.add_argument("--reranker", choices=["lexical", "cross-encoder"], default="lexical",
                    help="lexical baseline (default) or the frozen cross-encoder (needs the crossencoder extra)")
    ap.add_argument("--k", type=int, default=10)
    ap.add_argument("--out", default=None, help="write the full JSON report here")
    args = ap.parse_args()

    index = ReferenceIndex.from_seed() if args.seed else ReferenceIndex.load_default()
    ranker = CrossEncoderRanker(index) if args.reranker == "cross-encoder" else LexicalRanker(index)
    items = load_corpus(args.corpus)
    report = run_spike(items, ranker, index.version, k=args.k)

    _print_report(report)
    if args.out:
        pathlib.Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
