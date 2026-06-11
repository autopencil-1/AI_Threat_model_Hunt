from threat_agents.common.schema import DFD, DFDElement, ElementType, StrideCategory, Threat
from threat_agents.graphs.d1_stride.critic import coverage_critic
from threat_agents.graphs.d1_stride.stride_matrix import applicable_categories


def _full_coverage(dfd: DFD) -> list[Threat]:
    threats = []
    for el in dfd.stride_elements():
        for cat in applicable_categories(el):
            threats.append(Threat(id=f"{el.id}:{cat.value}", element_id=el.id, category=cat, description="x"))
    return threats


def test_full_coverage_passes():
    dfd = DFD(name="d", elements=[DFDElement(id="p", name="svc", type=ElementType.PROCESS)])
    res = coverage_critic(dfd, _full_coverage(dfd))
    assert res.ok
    assert res.gaps == []


def test_missing_category_is_a_gap():
    dfd = DFD(name="d", elements=[DFDElement(id="u", name="user", type=ElementType.EXTERNAL_ENTITY)])
    # external entity needs {S, R}; provide only S
    threats = [Threat(id="u:S", element_id="u", category=StrideCategory.SPOOFING, description="x")]
    res = coverage_critic(dfd, threats)
    assert not res.ok
    assert ("u", StrideCategory.REPUDIATION) in res.gaps


def test_explicit_na_determination_counts_as_covered():
    # An explicit, justified N/A determination (applicable=False) is "considered" -> not a gap.
    dfd = DFD(name="d", elements=[DFDElement(id="u", name="user", type=ElementType.EXTERNAL_ENTITY)])
    threats = [
        Threat(id="u:S", element_id="u", category=StrideCategory.SPOOFING, description="x"),
        Threat(id="u:R", element_id="u", category=StrideCategory.REPUDIATION,
               description="N/A: no auditable action", applicable=False),
    ]
    res = coverage_critic(dfd, threats)
    assert res.ok  # both applicable categories addressed (one as a real threat, one as N/A)


def test_ai_agent_element_requires_A():
    dfd = DFD(name="d", elements=[DFDElement(id="ai", name="agent", type=ElementType.PROCESS, is_ai_agent=True)])
    # cover full base STRIDE but omit the AI-agent "A" category
    threats = [
        Threat(id=f"ai:{c.value}", element_id="ai", category=c, description="x")
        for c in (StrideCategory.SPOOFING, StrideCategory.TAMPERING, StrideCategory.REPUDIATION,
                  StrideCategory.INFO_DISCLOSURE, StrideCategory.DENIAL_OF_SERVICE, StrideCategory.ELEVATION)
    ]
    res = coverage_critic(dfd, threats)
    assert not res.ok
    assert ("ai", StrideCategory.AI_AGENT) in res.gaps
