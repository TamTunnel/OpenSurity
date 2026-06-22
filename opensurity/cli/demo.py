import json
import logging
import os
import threading
import time
from http.server import HTTPServer
from pathlib import Path
from typing import Any, Dict

import typer

from opensurity.cli.main import RegistryHTTPRequestHandler
from opensurity.delegation.handshake import DelegationClient, DelegationServer, Message
from opensurity.identity.level1 import Level1Identity
from opensurity.manifest import AgentManifest
from opensurity.registry.local import LocalRegistry
from opensurity.log.store import TrustLogStore

logger = logging.getLogger(__name__)


def run_demo(num_agents: int = 3, registry_port: int = 7700) -> None:
    typer.secho("Starting OpenSurity Demo Pipeline...", fg=typer.colors.CYAN, bold=True)
    
    # 1. Start local registry
    registry = LocalRegistry()
    HTTPServer.allow_reuse_address = True
    registry_server = HTTPServer(("localhost", registry_port), RegistryHTTPRequestHandler)
    registry_thread = threading.Thread(target=registry_server.serve_forever, daemon=True)
    registry_thread.start()
    typer.echo(f"[1/4] Started local registry on port {registry_port}")

    # Wait for registry
    time.sleep(0.5)

    # 2. Start mock agent servers
    base_dir = Path("demo/agents")
    manifests = {
        "orchestrator": base_dir / "orchestrator.agent.json",
        "analyst": base_dir / "analyst.agent.json",
        "writer": base_dir / "writer.agent.json"
    }

    agents: Dict[str, Dict[str, Any]] = {}
    servers: Dict[str, DelegationServer] = {}

    for name, path in manifests.items():
        if not path.exists():
            typer.secho(f"Error: Manifest {path} not found. Run from repo root.", fg=typer.colors.RED)
            registry_server.shutdown()
            registry_server.server_close()
            return

        manifest = AgentManifest.from_file(path)
        identity = Level1Identity(agent_id=manifest.id)
        identity.generate() # Generate a fresh key for demo

        server = DelegationServer("localhost", 0, identity, registry.check_and_store_nonce)
        actual_port = server.server_port
        manifest.trust.endpoint = f"http://localhost:{actual_port}"
        
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        
        agents[name] = {"manifest": manifest, "identity": identity, "port": actual_port, "server": server}
        servers[name] = server
        
    ports_assigned = [a["port"] for a in agents.values()]
    typer.echo(f"[2/4] Started {num_agents} mock agent servers (ports {', '.join(map(str, ports_assigned))})")

    # Define handlers
    def handle_analyze(msg: Message) -> Dict[str, Any]:
        typer.secho(f"  -> Analyst received task from {msg.from_agent}: {msg.payload}", fg=typer.colors.YELLOW)
        time.sleep(0.5)
        from opensurity.log.events import TrustEvent
        from datetime import datetime, timezone
        import hashlib
        store = TrustLogStore()
        event = TrustEvent(
            version="0.1", agent=agents["analyst"]["manifest"].id, delegator=msg.from_agent,
            task_hash=hashlib.sha256(json.dumps(msg.payload, sort_keys=True).encode("utf-8")).hexdigest(),
            capability_used="analyze-text", outcome="success", duration_ms=500,
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            prev_cid=store.get_latest_cid(agents["analyst"]["manifest"].id)
        )
        event.sign(agents["analyst"]["identity"])
        store.append(event)
        return {"status": "success", "analysis": "This is a detailed analysis."}

    def handle_write(msg: Message) -> Dict[str, Any]:
        typer.secho(f"  -> Writer received task from {msg.from_agent}: {msg.payload}", fg=typer.colors.YELLOW)
        time.sleep(0.5)
        from opensurity.log.events import TrustEvent
        from datetime import datetime, timezone
        import hashlib
        store = TrustLogStore()
        event = TrustEvent(
            version="0.1", agent=agents["writer"]["manifest"].id, delegator=msg.from_agent,
            task_hash=hashlib.sha256(json.dumps(msg.payload, sort_keys=True).encode("utf-8")).hexdigest(),
            capability_used="write-summary", outcome="success", duration_ms=500,
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            prev_cid=store.get_latest_cid(agents["writer"]["manifest"].id)
        )
        event.sign(agents["writer"]["identity"])
        store.append(event)
        return {"status": "success", "summary": "This is a comprehensive summary."}

    servers["analyst"].register_handler("DELEGATE", handle_analyze)
    servers["writer"].register_handler("DELEGATE", handle_write)

    # 3. Register agents
    for name, agent_data in agents.items():
        registry.register(agent_data["manifest"])
    typer.echo(f"[3/4] Registered all {num_agents} agents in LocalRegistry")

    # 4. Execute pipeline
    typer.secho("[4/4] Executing demo pipeline:", fg=typer.colors.GREEN)
    
    orch_identity = agents["orchestrator"]["identity"]
    client = DelegationClient(orch_identity)
    
    typer.echo("  [Orchestrator] Task received: 'Analyze and summarize the OpenSurity README'")
    time.sleep(0.5)
    
    typer.echo("  [Orchestrator] Delegating analysis to Analyst...")
    analyst_result = client.delegate_task(agents["analyst"]["manifest"].trust.endpoint, agents["analyst"]["manifest"].id, {"task": "Analyze README"})
    typer.echo(f"  [Orchestrator] Received analysis result: {analyst_result.payload}")
    time.sleep(0.5)
    
    typer.echo("  [Orchestrator] Delegating writing to Writer...")
    writer_result = client.delegate_task(agents["writer"]["manifest"].trust.endpoint, agents["writer"]["manifest"].id, {"task": "Write summary based on analysis", "data": analyst_result.payload})
    typer.echo(f"  [Orchestrator] Received writer result: {writer_result.payload}")

    # Log Orchestrator TrustEvent
    from opensurity.log.events import TrustEvent
    from datetime import datetime, timezone
    import hashlib
    store = TrustLogStore()
    event = TrustEvent(
        version="0.1", agent=agents["orchestrator"]["manifest"].id, delegator=agents["orchestrator"]["manifest"].id,
        task_hash=hashlib.sha256(b"root task").hexdigest(),
        capability_used="orchestrate-pipeline", outcome="success", duration_ms=1000,
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        prev_cid=store.get_latest_cid(agents["orchestrator"]["manifest"].id)
    )
    event.sign(orch_identity)
    store.append(event)

    typer.secho("\nPipeline Complete!", fg=typer.colors.GREEN, bold=True)
    
    # 6. Print Trust Log Summary
    typer.secho("\n--- Trust Log Summary ---", fg=typer.colors.MAGENTA, bold=True)
    for name, agent_data in agents.items():
        agent_id = agent_data["manifest"].id
        latest_cid = store.get_latest_cid(agent_id)
        if latest_cid:
            chain = store.get_chain(latest_cid)
            typer.echo(f"{name.capitalize()} Agent ({agent_id}): {len(chain)} events logged. Latest outcome: {chain[-1].outcome}")
        else:
            typer.echo(f"{name.capitalize()} Agent ({agent_id}): 0 events logged.")

    # Shutdown servers cleanly so ports are freed
    typer.echo("\nShutting down demo servers...")
    registry_server.shutdown()
    registry_server.server_close()
    for s in servers.values():
        s.shutdown()
        s.server_close()
