import base64
from pathlib import Path
from typing import Tuple, Optional, Any, Dict

import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from opensurity.identity.base import Identity

class Level2Identity(Identity):
    """
    Level 2 Identity: W3C DID:key utilizing Ed25519 signatures.
    """

    ED25519_MULTICODEC_PREFIX = b"\xed\x01"

    def __init__(self, agent_id: str, key_dir: Optional[str] = None):
        import os
        if key_dir is None:
            key_dir = os.environ.get("OPENSURITY_KEY_DIR", "~/.opensurity/keys")
        self.agent_id = agent_id  # Expected to be a DID for L2
        self.key_dir = Path(key_dir).expanduser()
        self._private_key: Optional[ed25519.Ed25519PrivateKey] = None
        self._public_key: Optional[ed25519.Ed25519PublicKey] = None

    def _get_key_path(self) -> Path:
        self.key_dir.mkdir(parents=True, exist_ok=True)
        safe_name = self.agent_id.replace(":", "_")
        return self.key_dir / f"{safe_name}.key"

    def generate(self, agent_name: str = "") -> Tuple[str, str]:  # type: ignore[override]
        """
        Returns (did, private_key_base64url)
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        raw_pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        codec_bytes = self.ED25519_MULTICODEC_PREFIX + raw_pub_bytes
        base58_encoded = "z" + base58.b58encode(codec_bytes).decode('ascii')
        did = f"did:key:{base58_encoded}"

        raw_priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        priv_b64 = base64.urlsafe_b64encode(raw_priv_bytes).decode('ascii').rstrip("=")

        return did, priv_b64

    def save(self, private_key_b64: str) -> None:
        key_path = self._get_key_path()
        key_path.write_text(private_key_b64)
        key_path.chmod(0o600)
        self.load()

    def load(self) -> None:
        key_path = self._get_key_path()
        if not key_path.exists():
            raise FileNotFoundError(f"Key file not found at {key_path}")
            
        priv_b64 = key_path.read_text().strip()
        padding = '=' * (4 - len(priv_b64) % 4)
        raw_priv_bytes = base64.urlsafe_b64decode(priv_b64 + padding)
        
        self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_priv_bytes)
        self._public_key = self._private_key.public_key()

    def sign(self, message: bytes) -> str:
        if not self._private_key:
            self.load()
            
        assert self._private_key is not None
        signature = self._private_key.sign(message)
        return base64.urlsafe_b64encode(signature).decode('ascii').rstrip("=")

    def verify(self, message: bytes, signature: str, did: str) -> bool:
        if not did.startswith("did:key:z"):
            return False

        base58_part = did.split(":")[-1][1:] # strip "z"
        try:
            codec_bytes = base58.b58decode(base58_part)
            if not codec_bytes.startswith(self.ED25519_MULTICODEC_PREFIX):
                return False
                
            raw_pub_bytes = codec_bytes[len(self.ED25519_MULTICODEC_PREFIX):]
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(raw_pub_bytes)
            
            padding = '=' * (4 - len(signature) % 4)
            sig_bytes = base64.urlsafe_b64decode(signature + padding)
            
            public_key.verify(sig_bytes, message)
            return True
        except (ValueError, InvalidSignature):
            return False

    def resolve(self, did: str) -> Dict[str, Any]:
        if not did.startswith("did:key:z"):
            raise ValueError("Invalid did:key format")
            
        base58_part = did[8:]
        
        return {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            ],
            "id": did,
            "verificationMethod": [
                {
                    "id": f"{did}#{base58_part}",
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyMultibase": base58_part
                }
            ],
            "authentication": [f"{did}#{base58_part}"],
            "assertionMethod": [f"{did}#{base58_part}"],
            "capabilityDelegation": [f"{did}#{base58_part}"],
            "capabilityInvocation": [f"{did}#{base58_part}"]
        }

    def to_manifest_fragment(self) -> Dict[str, str]:
        return {
            "level": "did"
        }
