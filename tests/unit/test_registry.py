from pathlib import Path

import pytest

from opensurity.manifest import AgentManifest, Capability, TrustInfo
from opensurity.registry.local import LocalRegistry


@pytest.fixture
def registry(tmp_path: Path):
    return LocalRegistry(db_path=tmp_path / "registry.db")


def create_manifest(agent_id: str, cap_id: str, trust_level: str = "api-key") -> AgentManifest:
    return AgentManifest(
        opensurity="0.1",
        id=agent_id,
        name=f"Test Agent {agent_id}",
        version="1.0.0",
        capabilities=[
            Capability(id=cap_id, description="Test cap")
        ],
        trust=TrustInfo(level=trust_level, endpoint=f"http://localhost/{agent_id}"),
        framework="custom"
    )


def test_registry_register_and_get(registry: LocalRegistry):
    manifest = create_manifest("agent-1", "cap-a")
    registry.register(manifest)
    
    retrieved = registry.get("agent-1")
    assert retrieved is not None
    assert retrieved.id == "agent-1"
    assert retrieved.capabilities[0].id == "cap-a"


def test_registry_discover_ordering(registry: LocalRegistry):
    m1 = create_manifest("agent-1", "cap-target")
    m2 = create_manifest("agent-2", "cap-target")
    m3 = create_manifest("agent-3", "cap-other")
    
    registry.register(m1)
    registry.register(m2)
    registry.register(m3)
    
    # Update trust scores
    registry.update_trust_score("agent-1", 0.6)
    registry.update_trust_score("agent-2", 0.9)
    registry.update_trust_score("agent-3", 1.0)
    
    agents = registry.discover("cap-target")
    assert len(agents) == 2
    # Ordered by trust score descending
    assert agents[0].id == "agent-2"  # 0.9
    assert agents[1].id == "agent-1"  # 0.6


def test_registry_nonce_check(registry: LocalRegistry):
    assert registry.check_and_store_nonce("nonce-1", ttl_seconds=1) is True
    assert registry.check_and_store_nonce("nonce-1", ttl_seconds=1) is False
    assert registry.check_and_store_nonce("nonce-2", ttl_seconds=1) is True
