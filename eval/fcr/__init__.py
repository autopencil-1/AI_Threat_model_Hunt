"""Semantic-critic false-confirmation-rate (FCR) harness (05 §2.4 / C5).

The D3 semantic refinement critic runs in SHADOW mode (no gating authority) until its
false-confirmation rate clears a bound. This harness measures that rate the same way the spike
measures retrieval: generate labeled cases (a known-good tree = valid; deterministic semantic
mutations = invalid), run the critic, and compute:

  - FCR  = invalid cases the critic CONFIRMED (verdict=pass) / all invalid   (the dangerous error)
  - FRR  = valid cases the critic REJECTED / all valid                       (the annoying error)

Whether FCR clears the bound is a calibration decision for the floor-tuning owner; the threshold
here is a placeholder. Real expert-labeled cases plug in via the same `LabeledCase` list.
"""

from .metrics import FCRReport, false_confirmation_rate, false_rejection_rate, score
from .mutations import LabeledCase, good_trees, labeled_cases, mutate
from .run_fcr import run_fcr, semantic_critic_fn

__all__ = [
    "LabeledCase",
    "good_trees",
    "mutate",
    "labeled_cases",
    "false_confirmation_rate",
    "false_rejection_rate",
    "score",
    "FCRReport",
    "run_fcr",
    "semantic_critic_fn",
]
