"""STIX loader tests against a tiny synthetic bundle (no 50MB download needed in CI)."""

import json

from threat_agents.common.grounding.reference_index import ReferenceIndex

_BUNDLE = {
    "type": "bundle",
    "objects": [
        {"type": "x-mitre-collection", "name": "Enterprise ATT&CK", "x_mitre_version": "9.9"},
        {
            "type": "attack-pattern",
            "name": "Brute Force",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1110"}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
        },
        {
            "type": "attack-pattern",
            "name": "Password Spraying",  # sub-technique
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1110.003"}],
        },
        {
            "type": "attack-pattern",
            "name": "Deprecated Thing",
            "x_mitre_deprecated": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9998"}],
        },
        {
            "type": "attack-pattern",
            "name": "Revoked Thing",
            "revoked": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
        },
        {"type": "intrusion-set", "name": "Not A Technique"},
    ],
}


def _write(tmp_path):
    p = tmp_path / "enterprise-attack-9.9.json"
    p.write_text(json.dumps(_BUNDLE), encoding="utf-8")
    return p


def test_version_derived_from_collection(tmp_path):
    idx = ReferenceIndex.from_stix(_write(tmp_path))
    assert idx.version == "enterprise-attack-9.9"
    assert idx.content_hash and len(idx.content_hash) == 16


def test_explicit_version_overrides(tmp_path):
    idx = ReferenceIndex.from_stix(_write(tmp_path), version="pinned-x")
    assert idx.version == "pinned-x"


def test_techniques_loaded_and_filtered(tmp_path):
    idx = ReferenceIndex.from_stix(_write(tmp_path))
    assert "T1110" in idx
    assert idx.resolve("T1110").name == "Brute Force"
    assert "T1110.003" in idx  # sub-technique indexed directly
    assert "T9998" not in idx  # deprecated excluded
    assert "T9999" not in idx  # revoked excluded


def test_subtechnique_base_fallback(tmp_path):
    idx = ReferenceIndex.from_stix(_write(tmp_path))
    # an unlisted sub-technique resolves via its base technique
    assert "T1110.999" in idx
    assert idx.resolve("T1110.999").name == "Brute Force"


def test_grounding_hint_is_short_for_large_index():
    # The full ATT&CK is large -> hint must NOT inline the vocabulary.
    big = ReferenceIndex("big", {f"T{i:04d}": None for i in range(200)})  # type: ignore[arg-type]
    hint = big.grounding_hint()
    assert "T0000" not in hint
    assert "must exist in ATT&CK" in hint


def test_grounding_hint_inlines_for_seed():
    seed = ReferenceIndex.from_seed()
    assert "T1190" in seed.grounding_hint()  # small index inlines the vocabulary
