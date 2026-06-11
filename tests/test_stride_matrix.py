from threat_agents.common.schema import DFDElement, ElementType, StrideCategory
from threat_agents.graphs.d1_stride.stride_matrix import applicable_categories

S, T, R, I, D, E, A = (
    StrideCategory.SPOOFING,
    StrideCategory.TAMPERING,
    StrideCategory.REPUDIATION,
    StrideCategory.INFO_DISCLOSURE,
    StrideCategory.DENIAL_OF_SERVICE,
    StrideCategory.ELEVATION,
    StrideCategory.AI_AGENT,
)


def test_external_entity_is_spoofing_repudiation():
    el = DFDElement(id="u", name="user", type=ElementType.EXTERNAL_ENTITY)
    assert applicable_categories(el) == frozenset({S, R})


def test_process_is_full_stride():
    el = DFDElement(id="p", name="svc", type=ElementType.PROCESS)
    assert applicable_categories(el) == frozenset({S, T, R, I, D, E})


def test_ai_agent_adds_A_category():
    el = DFDElement(id="ai", name="agent", type=ElementType.PROCESS, is_ai_agent=True)
    assert A in applicable_categories(el)
    assert applicable_categories(el) == frozenset({S, T, R, I, D, E, A})


def test_data_store_and_flow():
    store = DFDElement(id="db", name="db", type=ElementType.DATA_STORE)
    flow = DFDElement(id="f", name="flow", type=ElementType.DATA_FLOW)
    assert applicable_categories(store) == frozenset({T, R, I, D})
    assert applicable_categories(flow) == frozenset({T, I, D})


def test_flow_crossing_trust_boundary_adds_spoofing():
    flow = DFDElement(id="f", name="flow", type=ElementType.DATA_FLOW, crosses_trust_boundary=True)
    assert applicable_categories(flow) == frozenset({S, T, I, D})
