import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from opensurity.cli.main import app

runner = CliRunner()


@pytest.fixture
def mock_keys_dir(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("OPENSURITY_KEY_DIR", str(tmp_path / ".opensurity" / "keys"))
    yield tmp_path


def test_cli_init(tmp_path: Path, mock_keys_dir: Path, monkeypatch):
    # Change to a temporary directory so we don't write agent.json to the real tree
    monkeypatch.chdir(tmp_path)
    
    result = runner.invoke(app, ["init", "--name", "TestAgent", "--framework", "langgraph"])
    
    assert result.exit_code == 0
    assert "Successfully initialized agent 'TestAgent'" in result.stdout
    assert "Agent ID:" in result.stdout
    
    # Check that agent.json was created
    manifest_path = tmp_path / "agent.json"
    assert manifest_path.exists()
    
    # Verify the contents of the manifest
    with open(manifest_path, "r") as f:
        data = json.load(f)
        
    assert data["name"] == "TestAgent"
    assert data["framework"] == "langgraph"
    assert data["trust"]["level"] == "api-key"
    assert len(data["capabilities"]) == 1
    
    # Check that the key file was created
    agent_id = data["id"]
    key_file = mock_keys_dir / ".opensurity" / "keys" / f"{agent_id}.key"
    assert key_file.exists()


def test_cli_init_already_exists(tmp_path: Path, mock_keys_dir: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    
    # Create a dummy agent.json
    (tmp_path / "agent.json").write_text("{}")
    
    result = runner.invoke(app, ["init", "--name", "TestAgent"])
    
    assert result.exit_code == 1
    assert "already exists" in result.stdout
