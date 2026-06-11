"""Historical-corpus schema + loader for the decision-gate spike.

A corpus item is an observation/CTI snippet with its known-outcome ATT&CK technique IDs. An empty
`ground_truth` marks a genuine no-mapping / novel case — important: those drive the miss-rate and
must NOT be silently dropped. Real corpora live in eval/corpora/ (gitignored); the committed
`sample_corpus.jsonl` is synthetic, for wiring/demo only.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

SAMPLE_CORPUS = Path(__file__).parent / "sample_corpus.jsonl"


class CorpusItem(BaseModel):
    id: str
    finding: str  # textual observation / CTI snippet
    ground_truth: list[str] = Field(default_factory=list)  # ATT&CK IDs; [] = genuine no-mapping
    tactic: str | None = None
    note: str | None = None


def load_corpus(path=SAMPLE_CORPUS) -> list[CorpusItem]:
    items: list[CorpusItem] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        items.append(CorpusItem.model_validate_json(line))
    return items
