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

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

_SEED = Path(__file__).parent / "_seed_attack.json"
# repo_root/data/attack — grounding(0)/common(1)/threat_agents(2)/src(3)/root(4)
_DATA_DIR = Path(__file__).resolve().parents[4] / "data" / "attack"


class UnresolvedTechniqueError(KeyError):
    """Raised when a technique ID fails the resolution invariant."""


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    description: str = ""


class ReferenceIndex:
    def __init__(
        self, version: str, techniques: dict[str, Technique], content_hash: str | None = None
    ):
        self.version = version
        self.content_hash = content_hash  # content-addressing (05 §2.2 / C2)
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

    def all(self) -> list[Technique]:
        return list(self._t.values())

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

    # Index size above which we stop inlining the full vocabulary into prompts.
    _INLINE_VOCAB_MAX = 80

    def grounding_hint(self) -> str:
        """Scale-aware grounding instruction for a worker prompt.

        Small index (seed): inline the whole vocabulary so a node can only cite resolvable IDs —
        a faithful Stage-1 stand-in for retrieval. Full ATT&CK: don't inline ~800+ techniques;
        instruct base-form IDs and let the (comprehensive) index + invariant do the enforcing.
        Stage 2 replaces both with KG-frontier retrieval of the top-k candidates per finding.
        """
        if len(self._t) <= self._INLINE_VOCAB_MAX:
            return (
                "Cite technique_ids ONLY from this ATT&CK list (use base IDs; [] if none apply):\n"
                + self.vocabulary()
            )
        return (
            f"Cite valid MITRE ATT&CK technique IDs in base form (e.g. T1110). "
            f"Every ID must exist in ATT&CK {self.version}."
        )

    @classmethod
    def from_seed(cls) -> "ReferenceIndex":
        data = json.loads(_SEED.read_text(encoding="utf-8"))
        techs = {
            t["id"]: Technique(
                t["id"], t["name"], tuple(t.get("tactics", [])), t.get("description", "")
            )
            for t in data["techniques"]
        }
        return cls(version=data["version"], techniques=techs)

    @classmethod
    def from_stix(cls, path, version: str | None = None) -> "ReferenceIndex":
        """Load a real ATT&CK STIX 2.1 bundle (e.g. enterprise-attack-18.0.json).

        Version is derived from the bundle's `x-mitre-collection` object when not given, so the
        pin is content-derived (e.g. 'enterprise-attack-18.0'); a sha256 content hash is recorded
        for content-addressing. Revoked/deprecated techniques are excluded; base techniques and
        sub-techniques (e.g. T1110.004) are both indexed.
        """
        raw = Path(path).read_bytes()
        content_hash = hashlib.sha256(raw).hexdigest()[:16]
        bundle = json.loads(raw.decode("utf-8"))

        collection = next(
            (o for o in bundle.get("objects", []) if o.get("type") == "x-mitre-collection"), None
        )
        derived = (
            f"enterprise-attack-{collection['x_mitre_version']}"
            if collection and collection.get("x_mitre_version")
            else None
        )
        resolved_version = version or derived or "enterprise-attack-unknown"

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
            if not tid:
                continue
            tactics = tuple(
                p.get("phase_name")
                for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            )
            techs[tid] = Technique(tid, obj.get("name", tid), tactics, obj.get("description", "") or "")
        return cls(version=resolved_version, techniques=techs, content_hash=content_hash)

    @classmethod
    def load_default(cls) -> "ReferenceIndex":
        """Best available index: $ATTACK_STIX_PATH, else newest data/attack bundle, else seed.

        Lets examples/runners use the full pinned ATT&CK when present and fall back to the seed
        offline (tests) with no code change.
        """
        env_path = os.environ.get("ATTACK_STIX_PATH")
        if env_path and Path(env_path).exists():
            return cls.from_stix(env_path)

        if _DATA_DIR.exists():
            def _vkey(fp: Path) -> tuple:
                m = re.search(r"enterprise-attack-([0-9.]+)\.json$", fp.name)
                return tuple(int(x) for x in m.group(1).split(".")) if m else (0,)

            files = sorted(_DATA_DIR.glob("enterprise-attack-*.json"), key=_vkey)
            if files:
                return cls.from_stix(files[-1])

        return cls.from_seed()
