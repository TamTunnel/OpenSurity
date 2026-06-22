import json
import socket
import time
from typing import Any, Dict

import pytest

from opensurity.delegation.handshake import DelegationClient, DelegationServer, Message
from opensurity.identity.level1 import Level1Identity
from opensurity.registry.local import LocalRegistry


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture
def identity_a():
    i = Level1Identity(agent_id="agent-a")
    i.generate()
    return i


@pytest.fixture
def identity_b():
    i = Level1Identity(agent_id="agent-b")
    i.generate()
    return i


@pytest.fixture
def registry(tmp_path):
    return LocalRegistry(db_path=tmp_path / "registry.db")


def test_handshake_flow(identity_a, identity_b, registry):
    port = get_free_port()
    
    # Setup Server B
    server_b = DelegationServer("localhost", port, identity_b, registry.check_and_store_nonce)
    
    def handle_delegate(msg: Message) -> Dict[str, Any]:
        # Step 4 logic: AgentB processes task
        assert msg.from_agent == "agent-a"
        assert msg.payload["task"] == "test-task"
        return {"status": "success", "result": "task-done", "event_cid": "cid-123"}
        
    server_b.register_handler("DELEGATE", handle_delegate)
    
    server_thread = server_b.start_background()
    time.sleep(0.5)  # wait for server to start
    
    try:
        # Setup Client A
        client_a = DelegationClient(identity_a)
        
        # Step 4 & 5: A sends DELEGATE, gets RESULT
        endpoint = f"http://localhost:{port}"
        
        result_msg = client_a.delegate_task(endpoint, "agent-b", {"task": "test-task"})
        
        assert result_msg.type == "RESULT"
        assert result_msg.from_agent == "agent-b"
        assert result_msg.to_agent == "agent-a"
        assert result_msg.payload["status"] == "success"
        
        # Test Replay Protection
        # We manually replay the exact same HTTP request
        msg_copy = Message(
            opensurity_msg="0.1",
            type="DELEGATE",
            from_agent="agent-a",
            to_agent="agent-b",
            nonce="replayed-nonce",
            timestamp="2026-06-23T00:00:00Z",
            payload={"task": "test-task"}
        )
        msg_copy.sign(identity_a)
        
        import urllib.request
        import urllib.error
        
        data = json.dumps(msg_copy.to_dict()).encode("utf-8")
        req = urllib.request.Request(endpoint, data=data, headers={"Content-Type": "application/json"})
        
        # First send should succeed
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            
        # Second send of exactly same nonce should fail with 500 (Internal server error from ValueError)
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req)
            
        assert exc_info.value.code == 500
        error_resp = json.loads(exc_info.value.read().decode("utf-8"))
        assert "Invalid or replayed nonce" in error_resp["details"]
        
    finally:
        server_b.shutdown()
        server_thread.join(timeout=2)
