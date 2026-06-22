import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    from crewai import Agent  # type: ignore
except ImportError as e:
    raise ImportError("opensurity[crewai] extra required: pip install opensurity[crewai]") from e

from opensurity.manifest import AgentManifest
from opensurity.identity.level1 import Level1Identity
from opensurity.log.events import TrustEvent
from opensurity.log.store import TrustLogStore
from opensurity.registry.local import LocalRegistry
from opensurity.wrappers.utils import extract_envelope, verify_inbound_signature

logger = logging.getLogger(__name__)

class TrustedAgent(Agent):
    def __init__(self, manifest: Any, *args: Any, **kwargs: Any) -> None:
        if isinstance(manifest, (str, Path)):
            self._opensurity_manifest = AgentManifest.from_file(Path(manifest))
        else:
            self._opensurity_manifest = manifest
            
        self._opensurity_manifest.validate()
        
        self._opensurity_identity = Level1Identity(agent_id=self._opensurity_manifest.id)
        self._opensurity_identity.load()
        
        self._trust_log_store = TrustLogStore()
        self._registry = LocalRegistry()
        
        super().__init__(*args, **kwargs)

    def execute_task(self, task: Any, context: Optional[str] = None, *args: Any, **kwargs: Any) -> str:
        delegator_id = self._opensurity_manifest.id
        
        envelope = None
        if isinstance(task, dict):
            envelope = extract_envelope(task, **kwargs)
        else:
            envelope = extract_envelope(**kwargs)
            
        if envelope:
            try:
                delegator_id = verify_inbound_signature(envelope, self._registry)
            except ValueError as e:
                logger.error(f"Signature verification failed: {e}")
                raise

        start_time = time.perf_counter()
        outcome = "success"
        result = None
        try:
            result = super().execute_task(task, context=context, *args, **kwargs)
        except ValueError:
            outcome = "failure"
            raise
        finally:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            
            cap_used = self.role if hasattr(self, "role") else "crewai-task"
            
            payload = envelope.get("payload", {}) if envelope else {}
            task_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
            task_hash = hashlib.sha256(task_bytes).hexdigest()

            prev_cid = self._trust_log_store.get_latest_cid(self._opensurity_manifest.id)
            
            event = TrustEvent(
                version="0.1",
                agent=self._opensurity_manifest.id,
                delegator=delegator_id,
                task_hash=task_hash,
                capability_used=cap_used,
                outcome=outcome,
                duration_ms=duration_ms,
                timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                prev_cid=prev_cid
            )
            
            event.sign(self._opensurity_identity)
            self._trust_log_store.append(event)
            
        return result
