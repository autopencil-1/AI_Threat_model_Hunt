"""Offline decision-gate spike (05 §A.2).

The gate that must run BEFORE any Stage-2 substrate/dispatcher is built. On a historical corpus
with known outcomes it measures two things and emits a FALSIFIABLE verdict:

  - miss-rate τ-sweep (test A / C3): how often KG-frontier retrieval scores nothing above τ.
  - re-ranker accuracy (B5): does the top candidate resolve to the *correct* technique.

A high miss-rate at sane τ, or a low re-ranker top-1, VETOES the tiered dispatcher design.
"""

from .corpus import CorpusItem, load_corpus
from .metrics import AccuracyReport, TauPoint, Verdict, gate_verdict, ranker_accuracy, tau_sweep
from .ranker import CrossEncoderRanker, LexicalRanker, Ranker
from .run_spike import run_spike

__all__ = [
    "CorpusItem",
    "load_corpus",
    "Ranker",
    "LexicalRanker",
    "CrossEncoderRanker",
    "tau_sweep",
    "ranker_accuracy",
    "gate_verdict",
    "TauPoint",
    "AccuracyReport",
    "Verdict",
    "run_spike",
]
