"""Append-only, version-pinned, replayable audit trace (05 §2.2 / C2).

Graph nodes emit `TraceNode`s into a state reducer (`Annotated[list[TraceNode], add]`) so
concurrent `Send` branches append safely; `AuditTrace.number()` finalizes ordering. Replay
is deterministic over (seq, graph, node, action, version, detail) — wall-clock `ts` is
excluded so a replay against the pinned reference index reproduces the same signature.
"""

from __future__ import annotations

import json
from pathlib import Path

from .schema import ConfidenceRecord, TraceNode


def trace_entry(
    run_id: str,
    ref_index_version: str,
    graph: str,
    node: str,
    action: str,
    detail: dict | None = None,
    confidence: ConfidenceRecord | None = None,
) -> TraceNode:
    """Build a single trace record (seq assigned later by `AuditTrace.number`)."""
    return TraceNode(
        run_id=run_id,
        ref_index_version=ref_index_version,
        graph=graph,
        node=node,
        action=action,
        detail=detail or {},
        confidence=confidence,
    )


class AuditTrace:
    def __init__(self, run_id: str, ref_index_version: str, graph: str):
        self.run_id = run_id
        self.ref_index_version = ref_index_version
        self.graph = graph
        self._nodes: list[TraceNode] = []

    def append(self, node: str, action: str, detail: dict | None = None) -> TraceNode:
        tn = trace_entry(self.run_id, self.ref_index_version, self.graph, node, action, detail)
        tn = tn.model_copy(update={"seq": len(self._nodes)})
        self._nodes.append(tn)
        return tn

    @property
    def nodes(self) -> list[TraceNode]:
        return list(self._nodes)

    @staticmethod
    def number(entries: list[TraceNode]) -> list[TraceNode]:
        """Finalize: assign monotonic seq by insertion order (entries gathered via a reducer)."""
        return [e.model_copy(update={"seq": i}) for i, e in enumerate(entries)]

    @staticmethod
    def to_jsonl(entries: list[TraceNode], path) -> None:
        Path(path).write_text(
            "\n".join(n.model_dump_json() for n in entries), encoding="utf-8"
        )

    @staticmethod
    def from_jsonl(path) -> list[TraceNode]:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        return [TraceNode.model_validate_json(line) for line in lines if line.strip()]

    @staticmethod
    def replay_signature(entries: list[TraceNode]) -> list[tuple]:
        """Deterministic replay signature; ignores wall-clock `ts`."""
        return [
            (
                n.seq,
                n.graph,
                n.node,
                n.action,
                n.ref_index_version,
                json.dumps(n.detail, sort_keys=True),
            )
            for n in entries
        ]
