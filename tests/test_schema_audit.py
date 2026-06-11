from threat_agents.common.audit import AuditTrace, trace_entry
from threat_agents.common.schema import ConfidenceRecord, CriticVerdict, Provenance


def test_confidence_record_defaults():
    c = ConfidenceRecord()
    assert c.critic_verdict == CriticVerdict.ABSTAIN
    assert c.provenance == Provenance.BASE
    assert c.attribution_class_ceiling == 1.0


def test_audit_trace_number_and_signature_is_deterministic():
    entries = [
        trace_entry("r", "v1", "D1-STRIDE", "ingest", "loaded_dfd", {"elements": 3}),
        trace_entry("r", "v1", "D1-STRIDE", "coverage_critic", "pass", {"gaps": []}),
    ]
    numbered = AuditTrace.number(entries)
    assert [n.seq for n in numbered] == [0, 1]

    # Replay signature ignores wall-clock ts and is stable across runs.
    sig1 = AuditTrace.replay_signature(numbered)
    sig2 = AuditTrace.replay_signature(AuditTrace.number(entries))
    assert sig1 == sig2


def test_audit_trace_jsonl_roundtrip(tmp_path):
    entries = AuditTrace.number(
        [trace_entry("r", "v1", "D3-ATTACK-TREE", "wf_critic", "pass", {"violations": []})]
    )
    path = tmp_path / "trace.jsonl"
    AuditTrace.to_jsonl(entries, path)
    loaded = AuditTrace.from_jsonl(path)
    assert AuditTrace.replay_signature(loaded) == AuditTrace.replay_signature(entries)
