import base64
import hashlib
import hmac
import logging
import os
import secrets
import stat
import uuid
from pathlib import Path
from typing import Dict, Any, Optional

from opensurity.identity.base import Identity

logger = logging.getLogger(__name__)


class Level1Identity(Identity):
    """Level 1 Identity using UUID and HMAC-SHA256."""

    def __init__(self, agent_id: Optional[str] = None, key_dir: Optional[str] = None):
        if key_dir is None:
            key_dir = os.environ.get("OPENSURITY_KEY_DIR", "~/.opensurity/keys")
        self.agent_id = agent_id or str(uuid.uuid4())
        self.key_dir = Path(key_dir).expanduser()
        self.secret_key: bytes = b""

    @property
    def key_path(self) -> Path:
        """Returns the path to the agent's key file."""
        self.key_dir.mkdir(parents=True, exist_ok=True)
        return self.key_dir / f"{self.agent_id}.key"

    def generate(self, name: str = "") -> None:
        """Generates a new UUID identity and saves the 32-byte secret key."""
        self.secret_key = secrets.token_bytes(32)
        
        path = self.key_path
        
        # Save key file, ensuring restrictive permissions
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.secret_key.hex())
            
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except (FileNotFoundError, PermissionError) as e:
            logger.warning(f"Could not set 0o600 permissions on key file: {e}")

    def load(self) -> None:
        """Loads the secret key from disk, enforcing 0o600 permissions on Unix."""
        path = self.key_path
        if not path.exists():
            raise FileNotFoundError(f"Key file not found: {path}")

        # Check permissions
        if os.name == "posix":
            st = os.stat(path)
            # Check if any group or others permissions are set
            if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise PermissionError(
                    f"Key file {path} has unsafe permissions. "
                    "Must be 0o600 (owner read/write only)."
                )
        else:
            logger.warning("Windows does not support Unix file permissions. Skipping 0o600 check.")

        with open(path, "r", encoding="utf-8") as f:
            self.secret_key = bytes.fromhex(f.read().strip())

    def sign(self, message: bytes) -> str:
        """Signs a message using HMAC-SHA256, returning a base64url-encoded string."""
        if not self.secret_key:
            self.load()
            
        h = hmac.new(self.secret_key, message, hashlib.sha256)
        sig_bytes = h.digest()
        # Use urlsafe base64 encoding without padding
        return base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode("ascii")

    def verify(self, message: bytes, signature: str, public_key: str) -> bool:
        """
        Verifies a signature. For Level 1 (HMAC), the public_key is not used 
        because verification requires the shared secret key.
        The verifier must have the same secret key loaded.
        """
        if not self.secret_key:
            self.load()
            
        expected_sig = self.sign(message)
        return hmac.compare_digest(expected_sig, signature)

    def to_manifest_fragment(self) -> Dict[str, Any]:
        """Returns the trust section fragment for the agent manifest."""
        return {
            "level": "api-key"
        }
