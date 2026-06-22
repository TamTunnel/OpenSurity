import logging
from typing import Any, Dict, Optional

from opensurity.identity.level1 import Level1Identity
from opensurity.delegation.handshake import Message
from opensurity.registry.local import LocalRegistry

logger = logging.getLogger(__name__)

def extract_envelope(*args: Any, **kwargs: Any) -> Optional[Dict[str, Any]]:
    """
    Attempts to extract an OpenSurity message envelope from arguments.
    Looks in kwargs for 'opensurity_envelope' or 'message' or '_opensurity_msg'.
    Also inspects the first positional argument (e.g., state in LangGraph).
    """
    for key in ("opensurity_envelope", "message", "_opensurity_msg"):
        if key in kwargs and isinstance(kwargs[key], dict):
            return kwargs[key]

    if args and isinstance(args[0], dict):
        state = args[0]
        # Look for nested envelope
        for key in ("opensurity_envelope", "message", "_opensurity_msg"):
            if key in state and isinstance(state[key], dict):
                return state[key]
        # Check if the state IS the envelope
        if "signature" in state and "nonce" in state and "type" in state:
            return state

    return None

def verify_inbound_signature(envelope: Dict[str, Any], registry: LocalRegistry) -> str:
    """
    Extracts the signature from the envelope and verifies it using the delegator's key.
    Returns the delegator's agent_id if successful.
    Raises ValueError if signature is missing or verification fails.
    """
    if "signature" not in envelope or not envelope["signature"]:
        raise ValueError("Missing signature in inbound call.")
        
    try:
        msg = Message.from_dict(envelope)
    except (FileNotFoundError, PermissionError, ValueError) as e:
        raise ValueError(f"Invalid message format: {e}") from e
        
    # Replay protection
    if not registry.check_and_store_nonce(msg.nonce):
        raise ValueError("Invalid or replayed nonce in envelope.")

    delegator_id = msg.from_agent

    # IMPORTANT LOCAL-ONLY ASSUMPTION:
    # The delegator signature verification here requires reading the delegator's key
    # from ~/.opensurity/keys/<delegator_id>.key. This only works if both agents
    # are running on the same machine (local dev). This must be updated to support
    # cross-org public key retrieval (e.g., L2 DID) in future versions.
    delegator_identity = Level1Identity(agent_id=delegator_id)
    try:
        delegator_identity.load()
    except (FileNotFoundError, PermissionError, ValueError) as e:
        raise ValueError(f"Could not load delegator key for {delegator_id}: {e}") from e

    if not msg.verify(delegator_identity):
        raise ValueError("Signature verification failed.")
        
    return delegator_id
