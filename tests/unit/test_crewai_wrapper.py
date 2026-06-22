import sys
import json
from unittest.mock import MagicMock
import pytest

# Mock crewai BEFORE importing the wrapper
mock_crewai = MagicMock()
class MockAgent:
    def __init__(self, *args, **kwargs):
        self.role = kwargs.get("role", "Mock Role")
    def execute_task(self, task, context=None, *args, **kwargs):
        return f"Executed: {task.get('task') if isinstance(task, dict) else task}"

mock_crewai.Agent = MockAgent
sys.modules["crewai"] = mock_crewai

from opensurity.wrappers.crewai import TrustedAgent  # noqa: E402
from opensurity.identity.level1 import Level1Identity  # noqa: E402
from opensurity.log.store import TrustLogStore  # noqa: E402
from opensurity.delegation.handshake import Message  # noqa: E402

@pytest.fixture
def manifest_file(tmp_path):
    manifest_data = {
        "opensurity": "0.1",
        "id": "agent-crew",
        "name": "CrewAIAgent",
        "version": "1.0.0",
        "capabilities": [{"id": "analysis", "description": "Analysis"}],
        "trust": {"level": "api-key"}
    }
    path = tmp_path / "agent.json"
    with open(path, "w") as f:
        json.dump(manifest_data, f)
    return str(path)

@pytest.fixture
def setup_identities(manifest_file):
    node_identity = Level1Identity(agent_id="agent-crew")
    node_identity.generate()

    delegator_identity = Level1Identity(agent_id="delegator-b")
    delegator_identity.generate()

    return node_identity, delegator_identity

def test_trusted_agent_success(manifest_file, setup_identities):
    node_identity, delegator_identity = setup_identities
    
    agent = TrustedAgent(manifest=manifest_file, role="Data Analyst")

    msg = Message(
        opensurity_msg="0.1",
        type="DELEGATE",
        from_agent="delegator-b",
        to_agent="agent-crew",
        nonce=__import__("uuid").uuid4().hex,
        timestamp="2026-06-23T00:00:00Z",
        payload={"task": "analyze data"}
    )
    msg.sign(delegator_identity)
    
    # Pass envelope in kwargs
    result = agent.execute_task(task="analyze data", opensurity_envelope=msg.to_dict())
    
    assert "Executed: analyze data" in result

    store = TrustLogStore()
    latest_cid = store.get_latest_cid("agent-crew")
    assert latest_cid is not None
    
    event = store.get(latest_cid)
    assert event.delegator == "delegator-b"
    assert event.outcome == "success"
    assert event.capability_used == "Data Analyst"
