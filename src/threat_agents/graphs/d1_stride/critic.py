"""D1 coverage critic — DETERMINISTIC structural (05 §2.1 / §2.4).

No LLM judgment, fully replayable, so it gates from day one: every DFD element must carry at
least one threat for every applicable STRIDE category. Any gap fails the critic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ...common.schema import DFD, StrideCategory, Threat
from .stride_matrix import applicable_categories


@dataclass
class CoverageResult:
    ok: bool
    gaps: list[tuple[str, StrideCategory]] = field(default_factory=list)
    covered: dict[str, set] = field(default_factory=dict)


def coverage_critic(dfd: DFD, threats: list[Threat]) -> CoverageResult:
    by_elem: dict[str, set] = {}
    for th in threats:
        by_elem.setdefault(th.element_id, set()).add(th.category)

    gaps: list[tuple[str, StrideCategory]] = []
    for el in dfd.stride_elements():
        required = applicable_categories(el)
        have = by_elem.get(el.id, set())
        for cat in sorted(required - have, key=lambda c: c.value):
            gaps.append((el.id, cat))

    return CoverageResult(ok=not gaps, gaps=gaps, covered=by_elem)
