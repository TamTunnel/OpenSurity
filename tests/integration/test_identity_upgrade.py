from pathlib import Path
from typer.testing import CliRunner
from opensurity.cli.main import app
from opensurity.manifest import AgentManifest
from opensurity.identity.level1 import Level1Identity
from opensurity.log.store import TrustLogStore

runner = CliRunner()

def test_identity_upgrade(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    # 1. Create L1 agent
    manifest_path = tmp_path / "agent.json"
    from opensurity.manifest import Capability, TrustInfo
    manifest = AgentManifest(
        opensurity="0.1",
        id="test-agent-1",
        name="TestAgent",
        version="0.1.0",
        capabilities=[Capability(id="test-cap", description="test")],
        trust=TrustInfo(level="api-key")
    )
    manifest.to_file(manifest_path)

    l1 = Level1Identity(agent_id=manifest.id)
    l1.generate() # Level1Identity generate handles secret internally and creates file for testing

    # 2. Add some trust logs
    store = TrustLogStore()
    from opensurity.log.events import TrustEvent
    e1 = TrustEvent(
        version="0.1",
        agent=manifest.id,
        delegator="delegator-1",
        task_hash="hash1",
        capability_used="test",
        outcome="success",
        duration_ms=100,
        timestamp="2026-06-23T00:00:00Z",
        prev_cid=None
    )
    e1.sign(l1)
    cid1 = store.append(e1)
    
    e2 = TrustEvent(
        version="0.1",
        agent=manifest.id,
        delegator="delegator-1",
        task_hash="hash2",
        capability_used="test",
        outcome="success",
        duration_ms=200,
        timestamp="2026-06-23T00:01:00Z",
        prev_cid=cid1
    )
    e2.sign(l1)
    store.append(e2)

    # 3. Run upgrade command
    result = runner.invoke(app, ["identity", "upgrade", "--manifest", str(manifest_path), "--level", "did-key"])
    assert result.exit_code == 0
    assert "Upgrade Complete!" in result.output

    # 4. Verify new manifest
    new_manifest = AgentManifest.from_file(manifest_path)
    assert new_manifest.id.startswith("did:key:z")
    assert new_manifest.trust.level == "did"

    # 5. Verify log re-signed
    latest = store.get_latest_cid(new_manifest.id)
    assert latest is not None
    chain = store.get_chain(latest)
    assert len(chain) == 2
    for e in chain:
        assert e.agent == new_manifest.id
        assert e.signature != ""

    # 6. Verify backups exist
    backups_dir = tmp_path / ".opensurity" / "backups"
    assert backups_dir.exists()
    dirs = list(backups_dir.iterdir())
    assert len(dirs) == 1
    bdir = dirs[0]
    assert (bdir / "agent.json.bak").exists()
    assert (bdir / "logs").exists()
