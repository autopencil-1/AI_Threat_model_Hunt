"""FCR harness runner (05 §2.4 / C5).

    python eval/fcr/run_fcr.py            # offline stub critic (deterministic demo)
    python eval/fcr/run_fcr.py --live     # real Anthropic critic (key from .env)

Generates labeled cases, runs the D3 semantic critic on each, and reports the false-confirmation
rate + whether it clears the (placeholder) gate. With the offline stub critic (which always says
"pass") FCR is 1.0 — correctly demonstrating that an uninformative critic must NOT be granted
gating authority.
"""

from __future__ import annotations

import dataclasses
import pathlib
import sys
from typing import Callable

_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

import argparse  # noqa: E402

from eval.fcr.metrics import FCRReport, score  # noqa: E402
from eval.fcr.mutations import LabeledCase, labeled_cases  # noqa: E402
from threat_agents.common.schema import AttackTreeNode  # noqa: E402
from threat_agents.graphs.d3_attack_tree.critic import (  # noqa: E402
    ShadowResult,
    semantic_refinement_critic,
)

CriticFn = Callable[[AttackTreeNode], ShadowResult]


def semantic_critic_fn(llm, model=None) -> CriticFn:
    return lambda tree: semantic_refinement_critic(llm, tree, model=model)


def run_fcr(cases: list[LabeledCase], critic_fn: CriticFn, *, fcr_ceiling: float = 0.1) -> FCRReport:
    results = [(case, critic_fn(case.tree).verdict == "pass") for case in cases]
    return score(results, fcr_ceiling=fcr_ceiling)


def _print(report: FCRReport, cases: list[LabeledCase]) -> None:
    print("=" * 78)
    print("SEMANTIC-CRITIC FCR HARNESS (05 §2.4 / C5) — earn gating authority before granting it")
    print("=" * 78)
    print(f"cases: {report.n}  ({report.n_valid} valid, {report.n_invalid} invalid)")
    print(f"FCR (false-confirmation rate, invalid confirmed): {report.fcr:.3f}  "
          f"[ceiling {report.fcr_ceiling}]")
    print(f"FRR (false-rejection rate, valid rejected):       {report.frr:.3f}")
    print(f"\nGATE: {'CLEARS' if report.clears_gate else 'DOES NOT CLEAR'}")
    print(f"  {report.recommendation}")
    print("=" * 78)


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the semantic-critic FCR harness.")
    ap.add_argument("--live", action="store_true", help="use the real Anthropic critic (.env)")
    ap.add_argument("--ceiling", type=float, default=0.1)
    args = ap.parse_args()

    if args.live:
        from threat_agents.common.config import anthropic_default_model, load_env
        from threat_agents.common.llm import AnthropicLLM

        load_env()
        llm = AnthropicLLM(default_model=anthropic_default_model())
        critic_fn = semantic_critic_fn(llm, model=anthropic_default_model())
    else:
        from threat_agents.common.testing import stub_tree_llm

        critic_fn = semantic_critic_fn(stub_tree_llm())

    cases = labeled_cases()
    report = run_fcr(cases, critic_fn, fcr_ceiling=args.ceiling)
    _print(report, cases)
    print(dataclasses.asdict(report))


if __name__ == "__main__":
    main()
