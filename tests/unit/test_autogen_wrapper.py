import sys
import json
from unittest.mock import MagicMock
import pytest

# Mock autogen BEFORE importing the wrapper
mock_autogen = MagicMock()
class MockAssistantAgent:
    def __init__(self, name, *args, **kwargs):
        self.name = name
    def generate_reply(self, messages=None, sender=None, **kwargs):
        return f"Reply from {self.name}"

mock_autogen.AssistantAgent = MockAssistantAgent
sys.modules["autogen"] = mock_autogen

from opensurity.wrappers.autogen import TrustedAssistantAgent  # noqa: E402
from opensurity.identity.level1 import Level1Identity  # noqa: E402
from opensurity.log.store import TrustLogStore  # noqa: E402
from opensurity.delegation.handshake import Message  # noqa: E402

@pytest.fixture
def manifest_file(tmp_path):
    manifest_data = {
        "opensurity": "0.1",
        "id": "agent-auto",
        "name": "AutoGenAgent",
        "version": "1.0.0",
        "capabilities": [{"id": "reply", "description": "Reply"}],
        "trust": {"level": "api-key"}
    }
    path = tmp_path / "agent.json"
    with open(path, "w") as f:
        json.dump(manifest_data, f)
    return str(path)

@pytest.fixture
def setup_identities(manifest_file):
    node_identity = Level1Identity(agent_id="agent-auto")
    node_identity.generate()

    delegator_identity = Level1Identity(agent_id="delegator-c")
    delegator_identity.generate()

    return node_identity, delegator_identity

def test_trusted_assistant_agent_success(manifest_file, setup_identities):
    node_identity, delegator_identity = setup_identities
    
    agent = TrustedAssistantAgent(manifest=manifest_file, name="assistant")

    msg = Message(
        opensurity_msg="0.1",
        type="DELEGATE",
        from_agent="delegator-c",
        to_agent="agent-auto",
        nonce=__import__("uuid").uuid4().hex,
        timestamp="2026-06-23T00:00:00Z",
        payload={"task": "hi"}
    )
    msg.sign(delegator_identity)
    
    messages = [
        {"role": "user", "content": "hi", "opensurity_envelope": msg.to_dict()}
    ]
    
    result = agent.generate_reply(messages=messages, sender=None)
    
    assert "Reply from assistant" in result

    store = TrustLogStore()
    latest_cid = store.get_latest_cid("agent-auto")
    assert latest_cid is not None
    
    event = store.get(latest_cid)
    assert event.delegator == "delegator-c"
    assert event.outcome == "success"
    assert event.capability_used == "assistant"
