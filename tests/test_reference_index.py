import pytest

from threat_agents.common.grounding.reference_index import (
    ReferenceIndex,
    UnresolvedTechniqueError,
)


@pytest.fixture
def index():
    return ReferenceIndex.from_seed()


def test_version_is_pinned(index):
    assert index.version.startswith("seed-")
    assert len(index) > 0


def test_resolve_known(index):
    t = index.resolve("T1190")
    assert t.name == "Exploit Public-Facing Application"


def test_resolve_unknown_raises(index):
    with pytest.raises(UnresolvedTechniqueError):
        index.resolve("T0000")


def test_enforce_resolves_invariant(index):
    index.enforce_resolves(["T1190", "T1078"])  # no raise
    with pytest.raises(UnresolvedTechniqueError):
        index.enforce_resolves(["T1190", "T9999"])
