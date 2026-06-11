"""Stage-1 lightweight, VERSIONED ATT&CK/CAPEC reference index.

Enforces the technique-ID-resolution INVARIANT against a PINNED version (05 §2.2 / C2): every
ATT&CK ID a graph emits must resolve to a known object in the run's index version, or it is a
hard failure. NOTE: resolution != correctness (B5) — whether an ID is the *right* technique is
measured separately (re-ranker accuracy) and only matters once the Stage-2 KG exists.

`from_seed()` loads a tiny bundled set so the scaffold runs offline. `from_stix()` is the
production path: a pinned ATT&CK STIX 2.1 bundle. Stage 2 replaces this whole module with the
content-addressed Neo4j KG + frozen re-ranker.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

_SEED = Path(__file__).parent / "_seed_attack.json"


class UnresolvedTechniqueError(KeyError):
    """Raised when a technique ID fails the resolution invariant."""


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]


class ReferenceIndex:
    def __init__(self, version: str, techniques: dict[str, Technique]):
        self.version = version
        self._t = techniques

    def __len__(self) -> int:
        return len(self._t)

    def _resolved_id(self, tid: object) -> str | None:
        """A sub-technique (e.g. 'T1110.004') resolves via its base technique ('T1110')."""
        if not isinstance(tid, str):
            return None
        if tid in self._t:
            return tid
        if "." in tid and tid.split(".", 1)[0] in self._t:
            return tid.split(".", 1)[0]
        return None

    def __contains__(self, tid: object) -> bool:
        return self._resolved_id(tid) is not None

    def get(self, tid: str) -> Technique | None:
        base = self._resolved_id(tid)
        return self._t.get(base) if base else None

    def resolve(self, tid: str) -> Technique:
        base = self._resolved_id(tid)
        if base is None:
            raise UnresolvedTechniqueError(
                f"{tid} does not resolve in reference index {self.version}"
            )
        return self._t[base]

    def enforce_resolves(self, ids) -> None:
        """The hard invariant. Call on every batch of technique IDs a node emits."""
        missing = [t for t in ids if self._resolved_id(t) is None]
        if missing:
            raise UnresolvedTechniqueError(
                f"unresolved technique IDs {missing} in reference index {self.version}"
            )

    def vocabulary(self, limit: int | None = None) -> str:
        """Compact 'id — name' listing to ground generation to the index (Stage-1 retrieval-lite).

        In Stage 2 this is replaced by KG-frontier retrieval of the top-k candidates per finding;
        here we surface the whole (small) index so a node cites only IDs that will resolve.
        """
        items = sorted(self._t.values(), key=lambda t: t.id)
        if limit:
            items = items[:limit]
        return "\n".join(f"{t.id} — {t.name}" for t in items)

    @classmethod
    def from_seed(cls) -> "ReferenceIndex":
        data = json.loads(_SEED.read_text(encoding="utf-8"))
        techs = {
            t["id"]: Technique(t["id"], t["name"], tuple(t.get("tactics", [])))
            for t in data["techniques"]
        }
        return cls(version=data["version"], techniques=techs)

    @classmethod
    def from_stix(cls, path, version: str) -> "ReferenceIndex":
        """Load a real ATT&CK STIX 2.1 bundle (e.g. enterprise-attack.json). Pin `version`."""
        bundle = json.loads(Path(path).read_text(encoding="utf-8"))
        techs: dict[str, Technique] = {}
        for obj in bundle.get("objects", []):
            if (
                obj.get("type") != "attack-pattern"
                or obj.get("revoked")
                or obj.get("x_mitre_deprecated")
            ):
                continue
            ext = [
                e
                for e in obj.get("external_references", [])
                if e.get("source_name") == "mitre-attack"
            ]
            if not ext:
                continue
            tid = ext[0].get("external_id")
            tactics = tuple(
                p.get("phase_name")
                for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            )
            techs[tid] = Technique(tid, obj.get("name", tid), tactics)
        return cls(version=version, techniques=techs)
