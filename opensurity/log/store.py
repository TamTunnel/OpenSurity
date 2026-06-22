import json
import logging
from pathlib import Path
from typing import List, Optional

from opensurity.log.events import TrustEvent
from opensurity.identity.base import Identity

logger = logging.getLogger(__name__)


class TrustLogStore:
    def __init__(self, base_dir: Optional[Path] = None, ipfs_url: Optional[str] = None):
        self.base_dir = base_dir or Path.home() / ".opensurity" / "logs"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.ipfs_url = ipfs_url
        if self.ipfs_url:
            logger.warning("IPFS support is not yet fully implemented.")

    def _agent_dir(self, agent_id: str) -> Path:
        agent_dir = self.base_dir / agent_id
        agent_dir.mkdir(parents=True, exist_ok=True)
        return agent_dir

    def append(self, event: TrustEvent) -> str:
        """Stores an event as a JSON file named by its CID."""
        if not event.cid:
            raise ValueError("Event must be signed and have a CID before appending.")

        agent_dir = self._agent_dir(event.agent)
        
        # Verify prev_cid matches the current HEAD
        current_head = self.get_latest_cid(event.agent)
        if current_head != event.prev_cid:
            raise ValueError(f"Chain mismatch: expected prev_cid {current_head}, got {event.prev_cid}")

        # Write the event file
        event_path = agent_dir / f"{event.cid}.json"
        with open(event_path, "w", encoding="utf-8") as f:
            json.dump(event._get_cid_dict(), f, indent=2, sort_keys=True)
            
        # Update HEAD
        head_path = agent_dir / "HEAD"
        with open(head_path, "w", encoding="utf-8") as f:
            f.write(event.cid)
            
        return event.cid

    def get(self, cid: str) -> TrustEvent:
        """Retrieves an event by CID."""
        # Search all agent directories for the CID
        for agent_dir in self.base_dir.iterdir():
            if agent_dir.is_dir():
                event_path = agent_dir / f"{cid}.json"
                if event_path.exists():
                    with open(event_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    event = TrustEvent.from_dict(data)
                    event.cid = cid  # Set the CID which is not in the JSON file
                    return event
                    
        raise FileNotFoundError(f"Event with CID {cid} not found.")

    def get_chain(self, tail_cid: str) -> List[TrustEvent]:
        """Traverses the linked list from tail to genesis, returns the full chain (oldest first)."""
        chain = []
        current_cid: Optional[str] = tail_cid
        
        while current_cid:
            event = self.get(current_cid)
            chain.append(event)
            current_cid = event.prev_cid
            
        # Return genesis-to-tail order
        chain.reverse()
        return chain

    def verify_chain(self, tail_cid: str, identity: Identity, public_key: str = "") -> bool:
        """
        Verifies every link in the chain.
        Returns True only if all CIDs match and all signatures verify.
        Note: The identity is required to verify the signatures.
        """
        try:
            chain = self.get_chain(tail_cid)
        except FileNotFoundError:
            return False

        expected_prev_cid = None
        
        for event in chain:
            # Check linkage
            if event.prev_cid != expected_prev_cid:
                logger.error(f"Linkage broken at event {event.cid}")
                return False
                
            # Check signature and internal CID
            if not event.verify(identity, public_key):
                logger.error(f"Signature or CID verification failed for event {event.cid}")
                return False
                
            expected_prev_cid = event.cid
            
        return True

    def get_latest_cid(self, agent_id: str) -> Optional[str]:
        """Returns the CID of the most recent event for this agent."""
        head_path = self._agent_dir(agent_id) / "HEAD"
        if not head_path.exists():
            return None
        with open(head_path, "r", encoding="utf-8") as f:
            return f.read().strip()
