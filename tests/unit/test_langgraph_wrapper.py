import sys
import json
from unittest.mock import MagicMock
import pytest

# Mock langgraph BEFORE importing the wrapper
sys.modules["langgraph"] = MagicMock()

from opensurity.wrappers.langgraph import trust_node  # noqa: E402
from opensurity.identity.level1 import Level1Identity  # noqa: E402
from opensurity.log.store import TrustLogStore  # noqa: E402
from opensurity.delegation.handshake import Message  # noqa: E402

@pytest.fixture
def manifest_file(tmp_path):
    manifest_data = {
        "opensurity": "0.1",
        "id": "agent-l1",
        "name": "LangGraphNode",
        "version": "1.0.0",
        "capabilities": [{"id": "test-cap", "description": "Test capability"}],
        "trust": {"level": "api-key"}
    }
    path = tmp_path / "agent.json"
    with open(path, "w") as f:
        json.dump(manifest_data, f)
    return str(path)

@pytest.fixture
def setup_identities(manifest_file):
    # Setup node identity
    node_identity = Level1Identity(agent_id="agent-l1")
    node_identity.generate()

    # Setup delegator identity
    delegator_identity = Level1Identity(agent_id="delegator-a")
    delegator_identity.generate()

    return node_identity, delegator_identity

def test_trust_node_success(manifest_file, setup_identities):
    node_identity, delegator_identity = setup_identities
    
    @trust_node(manifest=manifest_file, capability="test-cap")
    def my_node(state: dict) -> dict:
        return {"result": "success", "processed": True}

    msg = Message(
        opensurity_msg="0.1",
        type="DELEGATE",
        from_agent="delegator-a",
        to_agent="agent-l1",
        nonce=__import__("uuid").uuid4().hex,
        timestamp="2026-06-23T00:00:00Z",
        payload={"task": "do something"}
    )
    msg.sign(delegator_identity)
    
    state = {"opensurity_envelope": msg.to_dict()}
    result = my_node(state)
    
    assert result["processed"] is True

    store = TrustLogStore()
    latest_cid = store.get_latest_cid("agent-l1")
    assert latest_cid is not None
    
    event = store.get(latest_cid)
    assert event.delegator == "delegator-a"
    assert event.outcome == "success"
    assert event.capability_used == "test-cap"

def test_trust_node_unsigned(manifest_file, setup_identities):
    @trust_node(manifest=manifest_file)
    def my_node(state: dict) -> dict:
        return {"result": "ok"}
        
    result = my_node({})
    assert result["result"] == "ok"
    
    store = TrustLogStore()
    latest_cid = store.get_latest_cid("agent-l1")
    event = store.get(latest_cid)
    assert event.delegator == "agent-l1"

def test_trust_node_invalid_signature(manifest_file, setup_identities):
    node_identity, delegator_identity = setup_identities
    
    @trust_node(manifest=manifest_file)
    def my_node(state: dict) -> dict:
        return {}

    msg = Message(
        opensurity_msg="0.1",
        type="DELEGATE",
        from_agent="delegator-a",
        to_agent="agent-l1",
        nonce=__import__("uuid").uuid4().hex,
        timestamp="2026-06-23T00:00:00Z",
        payload={}
    )
    msg.sign(delegator_identity)
    
    env = msg.to_dict()
    env["signature"] += "invalid"
    
    state = {"opensurity_envelope": env}
    
    with pytest.raises(ValueError, match="Signature verification failed"):
        my_node(state)
