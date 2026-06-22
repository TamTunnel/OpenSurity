import os
import stat
from pathlib import Path

import pytest

from opensurity.identity.level1 import Level1Identity


@pytest.fixture
def mock_keys_dir(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("OPENSURITY_KEY_DIR", str(tmp_path / ".opensurity" / "keys"))
    yield tmp_path


def test_level1_generate_and_load(mock_keys_dir: Path):
    identity = Level1Identity(agent_id="test-agent-1")
    identity.generate()
    
    assert identity.secret_key != b""
    assert len(identity.secret_key) == 32
    
    # Verify file was created
    key_file = mock_keys_dir / ".opensurity" / "keys" / "test-agent-1.key"
    assert key_file.exists()
    
    # Test loading
    identity2 = Level1Identity(agent_id="test-agent-1")
    identity2.load()
    assert identity2.secret_key == identity.secret_key


def test_level1_sign_and_verify(mock_keys_dir: Path):
    identity = Level1Identity(agent_id="test-agent-2")
    identity.generate()
    
    message = b"test message"
    signature = identity.sign(message)
    
    assert isinstance(signature, str)
    
    # Should verify
    assert identity.verify(message, signature, public_key="")
    
    # Should fail on tampered message
    assert not identity.verify(b"tampered message", signature, public_key="")
    
    # Should fail on bad signature
    assert not identity.verify(message, "badsig", public_key="")


@pytest.mark.skipif(os.name != "posix", reason="Permissions test only applies to posix")
def test_level1_permission_enforcement(mock_keys_dir: Path):
    identity = Level1Identity(agent_id="test-agent-3")
    identity.generate()
    
    key_file = mock_keys_dir / ".opensurity" / "keys" / "test-agent-3.key"
    
    # It should have been created with safe permissions, so loading works
    identity.load()
    
    # Make permissions unsafe
    os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
    
    with pytest.raises(PermissionError, match="unsafe permissions"):
        identity.load()
