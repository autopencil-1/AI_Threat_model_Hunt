"""Checkpointer factory.

LangGraph checkpointers persist graph state at each superstep — this is what makes `interrupt()`
resumable and lets a run survive a process restart. `MemorySaver` is fine for tests/offline demos
but loses everything on exit; real runs (and the human gate, which may pause for hours) need a
durable backend. Stage 1 uses SQLite; the architecture names a full durable-execution layer
(Temporal/Restate) as a Stage-4 dependency for day-long hunts (05 §2.5).
"""

from __future__ import annotations

import pathlib
import sqlite3

DEFAULT_SQLITE_PATH = "./.threat_agents/checkpoints.sqlite"


def make_checkpointer(kind: str = "sqlite", path: str = DEFAULT_SQLITE_PATH):
    """Return a checkpointer. kind='memory' (ephemeral) or 'sqlite' (durable, default)."""
    if kind == "memory":
        from langgraph.checkpoint.memory import MemorySaver

        return MemorySaver()

    if kind == "sqlite":
        from langgraph.checkpoint.sqlite import SqliteSaver

        p = pathlib.Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: LangGraph executes nodes on a worker pool.
        conn = sqlite3.connect(str(p), check_same_thread=False)
        saver = SqliteSaver(conn)
        saver.setup()  # idempotent table creation
        return saver

    raise ValueError(f"unknown checkpointer kind: {kind!r} (use 'memory' or 'sqlite')")
