import time
from pathlib import Path
from typing import Optional

import pytest

from opensurity.identity.level1 import Level1Identity
from opensurity.log.events import TrustEvent
from opensurity.log.store import TrustLogStore


@pytest.fixture
def mock_keys_dir(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("OPENSURITY_KEY_DIR", str(tmp_path / ".opensurity" / "keys"))
    yield


@pytest.fixture
def identity(mock_keys_dir):
    identity = Level1Identity(agent_id="test-agent")
    identity.generate()
    return identity


@pytest.fixture
def store(tmp_path: Path):
    return TrustLogStore(base_dir=tmp_path / "logs")


def create_mock_event(agent: str, prev_cid: Optional[str] = None) -> TrustEvent:
    return TrustEvent(
        version="0.1",
        agent=agent,
        delegator="delegator-id",
        task_hash="fake-task-hash",
        capability_used="test-cap",
        outcome="success",
        duration_ms=100,
        timestamp="2026-06-23T00:00:00Z",
        prev_cid=prev_cid
    )


def test_event_creation_and_cid(identity: Level1Identity):
    event = create_mock_event(agent=identity.agent_id)
    event.sign(identity)
    
    assert event.signature != ""
    assert event.cid != ""
    assert event.verify(identity)


def test_chain_append_and_retrieval(identity: Level1Identity, store: TrustLogStore):
    # Event 1
    event1 = create_mock_event(agent=identity.agent_id)
    event1.sign(identity)
    cid1 = store.append(event1)
    
    assert store.get_latest_cid(identity.agent_id) == cid1
    
    # Event 2
    event2 = create_mock_event(agent=identity.agent_id, prev_cid=cid1)
    event2.sign(identity)
    cid2 = store.append(event2)
    
    assert store.get_latest_cid(identity.agent_id) == cid2
    
    # Retrieve chain
    chain = store.get_chain(cid2)
    assert len(chain) == 2
    assert chain[0].cid == cid1
    assert chain[1].cid == cid2


def test_chain_verification_tampering(identity: Level1Identity, store: TrustLogStore):
    event1 = create_mock_event(agent=identity.agent_id)
    event1.sign(identity)
    cid1 = store.append(event1)
    
    event2 = create_mock_event(agent=identity.agent_id, prev_cid=cid1)
    event2.sign(identity)
    cid2 = store.append(event2)
    
    # Valid chain
    assert store.verify_chain(cid2, identity)
    
    # Tamper with event1 on disk
    event_path = store._agent_dir(identity.agent_id) / f"{cid1}.json"
    with open(event_path, "r") as f:
        data = f.read()
    
    tampered_data = data.replace('"outcome": "success"', '"outcome": "failure"')
    with open(event_path, "w") as f:
        f.write(tampered_data)
        
    # Verification should now fail
    assert not store.verify_chain(cid2, identity)


def test_chain_verification_performance(identity: Level1Identity, store: TrustLogStore):
    """Chain with 100 events verifies in < 1 second."""
    num_events = 100
    prev_cid = None
    
    # Generate and append 100 events
    for _ in range(num_events):
        event = create_mock_event(agent=identity.agent_id, prev_cid=prev_cid)
        event.sign(identity)
        prev_cid = store.append(event)
        
    latest_cid = prev_cid
    assert latest_cid is not None
    
    # Measure verification time
    start_time = time.perf_counter()
    is_valid = store.verify_chain(latest_cid, identity)
    elapsed = time.perf_counter() - start_time
    
    assert is_valid
    assert elapsed < 1.0, f"Verification took {elapsed:.3f}s, expected < 1.0s"
