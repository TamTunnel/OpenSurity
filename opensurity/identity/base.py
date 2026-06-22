import abc
from typing import Dict, Any


class Identity(abc.ABC):
    """Abstract base class for OpenSurity agent identities."""
    
    agent_id: str

    @abc.abstractmethod
    def generate(self, name: str) -> None:
        """Generates a new identity and saves the private key."""
        pass

    @abc.abstractmethod
    def sign(self, message: bytes) -> str:
        """Signs a message using the identity's private key."""
        pass

    @abc.abstractmethod
    def verify(self, message: bytes, signature: str, public_key: str) -> bool:
        """Verifies a signature against the given message and public key."""
        pass

    @abc.abstractmethod
    def to_manifest_fragment(self) -> Dict[str, Any]:
        """Returns the trust section fragment for the agent manifest."""
        pass
