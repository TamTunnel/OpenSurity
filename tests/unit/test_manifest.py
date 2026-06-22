from pathlib import Path

import pytest

from opensurity.manifest import AgentManifest, Capability, TrustInfo, ManifestValidationError


def test_valid_manifest_serialization(tmp_path: Path):
    manifest = AgentManifest(
        opensurity="0.1",
        id="123e4567-e89b-12d3-a456-426614174000",
        name="TestAgent",
        version="1.0.0",
        capabilities=[
            Capability(id="test-cap", description="A test capability")
        ],
        trust=TrustInfo(level="api-key"),
        framework="custom"
    )
    
    # Test valid
    manifest.validate()
    
    # Test round trip to dict
    data = manifest.to_dict()
    assert data["name"] == "TestAgent"
    assert data["trust"]["level"] == "api-key"
    assert data["capabilities"][0]["id"] == "test-cap"
    
    # Test round trip to file
    file_path = tmp_path / "agent.json"
    manifest.to_file(file_path)
    
    loaded = AgentManifest.from_file(file_path)
    assert loaded.name == manifest.name
    assert loaded.id == manifest.id
    assert loaded.trust.level == manifest.trust.level
    assert loaded.capabilities[0].id == manifest.capabilities[0].id


def test_invalid_manifest_missing_required():
    with pytest.raises(ManifestValidationError):
        # Missing capabilities and trust
        manifest = AgentManifest(
            opensurity="0.1",
            id="1234",
            name="Test",
            version="1.0.0",
            capabilities=[],  # minItems is 1
            trust=TrustInfo(level="api-key")
        )
        manifest.validate()


def test_invalid_schema_version():
    manifest = AgentManifest(
        opensurity="invalid-version",
        id="1234",
        name="Test",
        version="1.0.0",
        capabilities=[Capability(id="cap", description="desc")],
        trust=TrustInfo(level="api-key")
    )
    with pytest.raises(ManifestValidationError):
        manifest.validate()


def test_load_invalid_json(tmp_path: Path):
    file_path = tmp_path / "bad.json"
    with open(file_path, "w") as f:
        f.write('{"opensurity": "0.1", "name": "Test"}') # Missing required fields
        
    with pytest.raises(ManifestValidationError):
        AgentManifest.from_file(file_path)
