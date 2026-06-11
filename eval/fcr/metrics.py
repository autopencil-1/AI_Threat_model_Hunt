"""FCR metrics (pure)."""

from __future__ import annotations

from dataclasses import dataclass

from .mutations import LabeledCase

# (case, confirmed) where confirmed == the critic returned verdict "pass"
Result = tuple[LabeledCase, bool]


def false_confirmation_rate(results: list[Result]) -> float:
    invalid = [(c, confirmed) for c, confirmed in results if not c.expected_valid]
    if not invalid:
        return 0.0
    return sum(1 for _, confirmed in invalid if confirmed) / len(invalid)


def false_rejection_rate(results: list[Result]) -> float:
    valid = [(c, confirmed) for c, confirmed in results if c.expected_valid]
    if not valid:
        return 0.0
    return sum(1 for _, confirmed in valid if not confirmed) / len(valid)


@dataclass
class FCRReport:
    n: int
    n_valid: int
    n_invalid: int
    fcr: float
    frr: float
    fcr_ceiling: float
    clears_gate: bool
    recommendation: str


def score(results: list[Result], *, fcr_ceiling: float = 0.1) -> FCRReport:
    fcr = false_confirmation_rate(results)
    frr = false_rejection_rate(results)
    clears = fcr <= fcr_ceiling
    rec = (
        "FCR within bound — the floor-tuning owner MAY grant the semantic critic gating authority "
        "(flip SEMANTIC_CRITIC_HAS_GATING_AUTHORITY), subject to calibration on real labels."
        if clears
        else "FCR exceeds bound — the semantic critic STAYS in shadow mode (no gating authority, C5)."
    )
    n_valid = sum(1 for c, _ in results if c.expected_valid)
    return FCRReport(
        n=len(results),
        n_valid=n_valid,
        n_invalid=len(results) - n_valid,
        fcr=round(fcr, 4),
        frr=round(frr, 4),
        fcr_ceiling=fcr_ceiling,
        clears_gate=clears,
        recommendation=rec,
    )
