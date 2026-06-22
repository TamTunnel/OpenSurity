import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional

try:
    import langgraph  # type: ignore # noqa: F401
except ImportError as e:
    raise ImportError("opensurity[langgraph] extra required: pip install opensurity[langgraph]") from e

from opensurity.manifest import AgentManifest
from opensurity.identity.level1 import Level1Identity
from opensurity.log.events import TrustEvent
from opensurity.log.store import TrustLogStore
from opensurity.registry.local import LocalRegistry
from opensurity.wrappers.utils import extract_envelope, verify_inbound_signature

logger = logging.getLogger(__name__)

def trust_node(manifest: str, capability: Optional[str] = None) -> Callable:
    """
    A decorator for LangGraph nodes that verifies inbound signatures and logs TrustEvents.
    """
    _manifest_loaded = False
    _agent_manifest: Optional[AgentManifest] = None
    _agent_identity: Optional[Level1Identity] = None
    _trust_log_store = TrustLogStore()
    _registry = LocalRegistry()

    def load_manifest() -> None:
        nonlocal _manifest_loaded, _agent_manifest, _agent_identity
        if not _manifest_loaded:
            _agent_manifest = AgentManifest.from_file(Path(manifest))
            _agent_manifest.validate()
            _agent_identity = Level1Identity(agent_id=_agent_manifest.id)
            _agent_identity.load()
            _manifest_loaded = True

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            load_manifest()
            
            assert _agent_manifest is not None
            assert _agent_identity is not None

            delegator_id = _agent_manifest.id # Default to self if unsigned
            envelope = extract_envelope(*args, **kwargs)
            
            if envelope:
                # Inbound call: verify signature
                try:
                    delegator_id = verify_inbound_signature(envelope, _registry)
                except ValueError as e:
                    logger.error(f"Signature verification failed: {e}")
                    raise

            # Execute
            start_time = time.perf_counter()
            outcome = "success"
            result = None
            try:
                result = func(*args, **kwargs)
            except ValueError:
                outcome = "failure"
                raise
            finally:
                duration_ms = int((time.perf_counter() - start_time) * 1000)
                
                # Determine capability
                cap_used = capability or func.__name__
                
                # Payload hashing
                payload = envelope.get("payload", {}) if envelope else {}
                task_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
                task_hash = hashlib.sha256(task_bytes).hexdigest()

                prev_cid = _trust_log_store.get_latest_cid(_agent_manifest.id)
                
                event = TrustEvent(
                    version="0.1",
                    agent=_agent_manifest.id,
                    delegator=delegator_id,
                    task_hash=task_hash,
                    capability_used=cap_used,
                    outcome=outcome,
                    duration_ms=duration_ms,
                    timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    prev_cid=prev_cid
                )
                
                event.sign(_agent_identity)
                _trust_log_store.append(event)
                
            return result
        return wrapper
    return decorator
