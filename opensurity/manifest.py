import json
import logging
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Optional, Any

import jsonschema

logger = logging.getLogger(__name__)

MANIFEST_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "https://opensurity.dev/schemas/v0.1/agent.json",
    "type": "object",
    "required": ["opensurity", "id", "name", "version", "capabilities", "trust"],
    "properties": {
        "opensurity": {
            "type": "string",
            "pattern": "^0\\.[0-9]+$",
            "description": "OpenSurity schema version"
        },
        "id": {
            "type": "string",
            "description": "UUID (L1) or W3C DID (L2+)"
        },
        "name": {
            "type": "string",
            "maxLength": 64
        },
        "version": {
            "type": "string",
            "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$"
        },
        "capabilities": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["id", "description"],
                "properties": {
                    "id": {"type": "string"},
                    "description": {"type": "string"},
                    "input": {"type": "string"},
                    "output": {"type": "string"}
                }
            }
        },
        "trust": {
            "type": "object",
            "required": ["level"],
            "properties": {
                "level": {"type": "string", "enum": ["api-key", "did", "zkp"]},
                "endpoint": {"type": "string", "format": "uri"},
                "log": {"type": "string"},
                "public_key": {"type": "string"}
            }
        },
        "framework": {
            "type": "string",
            "enum": ["langgraph", "crewai", "autogen", "custom"]
        },
        "contact": {"type": "string"}
    }
}


class ManifestValidationError(Exception):
    """Raised when an agent manifest fails schema validation."""
    pass


@dataclass
class Capability:
    id: str
    description: str
    input: Optional[str] = None
    output: Optional[str] = None


@dataclass
class TrustInfo:
    level: str
    endpoint: Optional[str] = None
    log: Optional[str] = None
    public_key: Optional[str] = None


@dataclass
class AgentManifest:
    opensurity: str
    id: str
    name: str
    version: str
    capabilities: List[Capability]
    trust: TrustInfo
    framework: Optional[str] = None
    contact: Optional[str] = None

    def validate(self) -> None:
        """Validates the current state of the manifest against the JSON schema."""
        try:
            jsonschema.validate(instance=self.to_dict(), schema=MANIFEST_SCHEMA)
        except jsonschema.ValidationError as e:
            raise ManifestValidationError(f"Invalid manifest: {e.message}") from e

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the manifest to a dictionary, omitting None values."""
        def exclude_none(items: List[Any]) -> Dict[str, Any]:
            return {k: v for k, v in items if v is not None}
        return asdict(self, dict_factory=exclude_none)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentManifest":
        """Creates an AgentManifest from a dictionary without mutating the input."""
        data_copy = data.copy()
        
        if "capabilities" in data_copy:
            data_copy["capabilities"] = [
                Capability(**cap) if isinstance(cap, dict) else cap
                for cap in data_copy["capabilities"]
            ]
        if "trust" in data_copy and isinstance(data_copy["trust"], dict):
            data_copy["trust"] = TrustInfo(**data_copy["trust"])
            
        return cls(**data_copy)

    @classmethod
    def from_file(cls, path: Path) -> "AgentManifest":
        """Loads and validates an agent manifest from a JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        try:
            jsonschema.validate(instance=data, schema=MANIFEST_SCHEMA)
        except jsonschema.ValidationError as e:
            raise ManifestValidationError(f"Invalid manifest file: {e.message}") from e
            
        return cls.from_dict(data)

    def to_file(self, path: Path) -> None:
        """Validates and saves the agent manifest to a JSON file."""
        self.validate()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
