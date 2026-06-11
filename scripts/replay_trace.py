"""Load a persisted audit trace (JSONL) and print its deterministic replay signature.

    python scripts/replay_trace.py path/to/trace.jsonl

Replay is pinned to the trace's `ref_index_version` and excludes wall-clock `ts` (05 §2.2 / C2),
so two runs over the same pinned index produce identical signatures — that's the auditability claim.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from threat_agents.common.audit import AuditTrace  # noqa: E402


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: python scripts/replay_trace.py <trace.jsonl>")
    entries = AuditTrace.from_jsonl(sys.argv[1])
    versions = sorted({e.ref_index_version for e in entries})
    print(f"{len(entries)} trace records  |  pinned versions: {versions}")
    for seq, graph, node, action, version, detail in AuditTrace.replay_signature(entries):
        print(f"  [{seq:>3}] {graph:<16} {node:<22} {action:<14} {detail}")


if __name__ == "__main__":
    main()
