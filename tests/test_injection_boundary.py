from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from threat_agents.common.grounding.reference_index import ReferenceIndex
from threat_agents.common.injection_boundary import IngestionBoundary
from threat_agents.common.integrations.stubs import StdoutApprovalQueue
from threat_agents.common.testing import stub_tree_llm
from threat_agents.graphs.d3_attack_tree import build_d3_graph


def test_control_chars_stripped():
    b = IngestionBoundary()
    out = b.sanitize("hello\x00\x07world\x1f")
    assert out.text == "helloworld"


def test_ip_and_email_pseudonymized_deterministically():
    b = IngestionBoundary()
    s1 = b.sanitize("attacker 10.0.0.5 mailed admin@corp.com")
    s2 = b.sanitize("attacker 10.0.0.5 mailed admin@corp.com")
    assert "10.0.0.5" not in s1.text and "admin@corp.com" not in s1.text
    assert "<ip:" in s1.text and "<email:" in s1.text
    assert s1.text == s2.text  # deterministic (hash-based), replayable
    assert s1.redactions == {"ip": 1, "email": 1}


def test_size_bound():
    b = IngestionBoundary(max_bytes=10)
    out = b.sanitize("x" * 100)
    assert out.truncated and len(out.text) <= 10


def test_d3_ingest_sanitizes_untrusted_goal():
    app = build_d3_graph(stub_tree_llm(), ReferenceIndex.from_seed(), StdoutApprovalQueue(),
                         MemorySaver(), max_depth=2)
    cfg = {"configurable": {"thread_id": "inj-d3"}}
    paused = app.invoke({"run_id": "r", "goal": "Exfiltrate from 192.168.1.9\x07 now"}, cfg)
    assert "__interrupt__" in paused
    final = app.invoke(Command(resume={"approved": True}), cfg)
    root_goal = final["tree"].goal
    assert "192.168.1.9" not in root_goal  # raw IP gone
    assert "<ip:" in root_goal  # pseudonymized
    assert "\x07" not in root_goal  # control char stripped
