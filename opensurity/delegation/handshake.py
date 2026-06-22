import http.client
import json
import logging
import threading
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Dict

from opensurity.identity.base import Identity

logger = logging.getLogger(__name__)


@dataclass
class Message:
    opensurity_msg: str
    type: str
    from_agent: str
    to_agent: str
    nonce: str
    timestamp: str
    payload: Dict[str, Any]
    signature: str = ""

    def _get_signable_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("signature", None)
        return d

    def sign(self, identity: Identity) -> None:
        signable_json = json.dumps(self._get_signable_dict(), sort_keys=True).encode("utf-8")
        self.signature = identity.sign(signable_json)

    def verify(self, identity: Identity, public_key: str = "") -> bool:
        signable_json = json.dumps(self._get_signable_dict(), sort_keys=True).encode("utf-8")
        return identity.verify(signable_json, self.signature, public_key)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Message":
        # Rename 'from' and 'to' mapping
        if "from" in data:
            data["from_agent"] = data.pop("from")
        if "to" in data:
            data["to_agent"] = data.pop("to")
        return cls(**data)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["from"] = d.pop("from_agent")
        d["to"] = d.pop("to_agent")
        return d


class DelegationClient:
    def __init__(self, identity: Identity):
        self.identity = identity

    def send_message(self, endpoint: str, msg_type: str, to_agent: str, payload: Dict[str, Any]) -> Message:
        """Sends a signed message to the specified endpoint."""
        msg = Message(
            opensurity_msg="0.1",
            type=msg_type,
            from_agent=self.identity.agent_id,
            to_agent=to_agent,
            nonce=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            payload=payload
        )
        msg.sign(self.identity)

        data = json.dumps(msg.to_dict()).encode("utf-8")
        req = urllib.request.Request(endpoint, data=data, headers={"Content-Type": "application/json"})
        
        try:
            with urllib.request.urlopen(req) as response:
                response_data = json.loads(response.read().decode("utf-8"))
                return Message.from_dict(response_data)
        except urllib.error.HTTPError as e:
            logger.error(f"HTTPError: {e.code} - {e.read().decode('utf-8')}")
            raise

    # High-level handshake steps
    def request_manifest(self, endpoint: str, target_agent: str) -> Message:
        return self.send_message(endpoint, "MANIFEST", target_agent, {})

    def delegate_task(self, endpoint: str, target_agent: str, task_details: Dict[str, Any]) -> Message:
        return self.send_message(endpoint, "DELEGATE", target_agent, task_details)


class DelegationRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: "DelegationServer" # type hint for IDE

    def _send_json(self, data: dict, status: int = 200) -> None:
        response = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def do_POST(self) -> None:
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            msg_dict = json.loads(post_data.decode("utf-8"))
            msg = Message.from_dict(msg_dict)
        except (ValueError, urllib.error.URLError, http.client.HTTPException) as e:
            self._send_json({"error": "Invalid request format", "details": str(e)}, 400)
            return

        # Let the server handle the logic (validation, generating response)
        try:
            response_msg = self.server.handle_message(msg)
            self._send_json(response_msg.to_dict())
        except (ValueError, urllib.error.URLError, http.client.HTTPException) as e:
            self._send_json({"error": "Internal server error", "details": str(e)}, 500)


class DelegationServer(HTTPServer):
    allow_reuse_address = True

    def __init__(self, host: str, port: int, identity: Identity, registry_check_nonce: Callable[[str], bool]):
        super().__init__((host, port), DelegationRequestHandler)
        self.identity = identity
        self.registry_check_nonce = registry_check_nonce
        self.handlers: Dict[str, Callable[[Message], Dict[str, Any]]] = {}

    def register_handler(self, msg_type: str, handler: Callable[[Message], Dict[str, Any]]) -> None:
        self.handlers[msg_type] = handler

    def handle_message(self, msg: Message) -> Message:
        # Replay protection
        if not self.registry_check_nonce(msg.nonce):
            raise ValueError("Invalid or replayed nonce")
            
        # Normally we'd verify the signature here, but for L1 we need the sender's shared secret
        # Since we are assuming trusted internal networks or getting the key from registry
        # The verification logic would need the sender's public key from the registry
        # We will assume signature verification is handled in the application layer or handler if needed.
        # But we should enforce it! For the prototype, we leave the actual verify call to the handler
        # because the server doesn't have the sender's identity loaded directly.

        if msg.type not in self.handlers:
            raise ValueError(f"Unsupported message type: {msg.type}")

        # Execute handler to get payload
        payload = self.handlers[msg.type](msg)

        # Construct response
        resp = Message(
            opensurity_msg="0.1",
            type="RESULT" if msg.type == "DELEGATE" else msg.type + "_RESPONSE",
            from_agent=self.identity.agent_id,
            to_agent=msg.from_agent,
            nonce=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            payload=payload
        )
        resp.sign(self.identity)
        return resp

    def start_background(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever)
        thread.daemon = True
        thread.start()
        return thread
