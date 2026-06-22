import hashlib
import json
from dataclasses import dataclass, asdict
from typing import Optional, Any, Dict

from opensurity.identity.base import Identity


@dataclass
class TrustEvent:
    version: str
    agent: str
    delegator: str
    task_hash: str
    capability_used: str
    outcome: str
    duration_ms: int
    timestamp: str
    prev_cid: Optional[str]
    signature: str = ""
    cid: str = ""

    def _get_signable_dict(self) -> Dict[str, Any]:
        """Returns the dictionary representation excluding signature and cid."""
        d = asdict(self)
        d.pop("signature", None)
        d.pop("cid", None)
        return d

    def _get_cid_dict(self) -> Dict[str, Any]:
        """Returns the dictionary representation excluding cid, but including signature."""
        d = asdict(self)
        d.pop("cid", None)
        return d

    def sign(self, identity: Identity) -> None:
        """Signs the event using the provided identity and sets the signature and cid."""
        signable_json = json.dumps(self._get_signable_dict(), sort_keys=True).encode("utf-8")
        self.signature = identity.sign(signable_json)
        
        cid_json = json.dumps(self._get_cid_dict(), sort_keys=True).encode("utf-8")
        self.cid = hashlib.sha256(cid_json).hexdigest()

    def verify(self, identity: Identity, public_key: str = "") -> bool:
        """
        Verifies the signature and CID of the event.
        For L1, public_key is not used. The identity must have the shared secret loaded.
        """
        # 1. Verify CID
        cid_json = json.dumps(self._get_cid_dict(), sort_keys=True).encode("utf-8")
        expected_cid = hashlib.sha256(cid_json).hexdigest()
        if self.cid != expected_cid:
            return False

        # 2. Verify Signature
        signable_json = json.dumps(self._get_signable_dict(), sort_keys=True).encode("utf-8")
        key_to_use = public_key or getattr(identity, 'agent_id', self.agent)
        return identity.verify(signable_json, self.signature, key_to_use)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrustEvent":
        """Creates a TrustEvent from a dictionary."""
        return cls(**data)
