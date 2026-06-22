# OpenSurity

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Python Version](https://img.shields.io/badge/python-%3E%3D3.11-blue)

OpenSurity is the connective tissue layer for AI agent networks. It provides a progressive identity system, a tamper-evident behavioral trust log, and a capability discovery bus that allows autonomous agents to securely discover and delegate tasks to one another.

**OpenSurity is a lightweight standard and verification protocol for multi-agent interoperability. It is NOT:**

- An AI orchestrator or inference engine.
- An LLM execution environment or prompt layer.
- A centralized agent marketplace.
- A blockchain product or distributed ledger.

## The Problem

As autonomous AI agents proliferate across LangGraph, CrewAI, AutoGen, and custom frameworks, they remain heavily siloed. If a LangGraph Orchestrator needs to delegate data-parsing to a CrewAI Analyst, there is no shared trust boundary, no cryptographic way to verify the remote agent's identity, and no immutable record of what task was delegated and whether it succeeded.

## The Solution (In Layman's Terms)

Think of OpenSurity as a **passport and ledger system** for AI agents.
Before two agents communicate, OpenSurity steps in to check their "passports" (cryptographic keys). When an agent delegates a task, OpenSurity logs exactly what was requested and what the outcome was into an indestructible "ledger" (a tamper-evident append-only log).

## Quick Setup Guide

From a fresh Python 3.11+ environment, run the following commands to see the 3-agent delegation pipeline in action:

```bash
git clone https://github.com/your-org/opensurity.git
cd opensurity
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install .
opensurity demo --agents 3
```

## Architecture

```text
+-----------------------+      +-----------------------+
|   Agent Framework A   |      |   Agent Framework B   |
|  (LangGraph/CrewAI)   |      |      (AutoGen)        |
|      +---------+      |      |      +---------+      |
|      | Wrapper |      |      |      | Wrapper |      |
+------+----+----+------+      +------+----+----+------+
            |                              |
            |   5-Step Handshake (HTTP)    |
            +------------------------------+
            |
    +-------v--------+
    | Local Registry | <-- Capability Discovery
    |  Trust Log DB  | <-- Append-only Behaviors
    +----------------+
```

## Progressive Trust Levels

| Level | Name           | Description                                                      | Verification                                            |
| ----- | -------------- | ---------------------------------------------------------------- | ------------------------------------------------------- |
| L1    | Pre-shared Key | Internal agents within the same organization trust boundary.     | HMAC-SHA256 signature verification via local key paths. |
| L2    | Public PKI     | Cross-organizational agents identifying via decentralized means. | Ed25519 signature verification via W3C DID (did:key).   |
| L3    | Zero-Knowledge | Anonymous agent verification ensuring privacy guarantees.        | ZK-SNARK proof verification (Future).                   |

## Framework Wrappers

OpenSurity offers framework-agnostic SDK wrappers that transparently verify identity and log trust events.

**LangGraph:**

```python
from opensurity.wrappers.langgraph import trust_node

@trust_node(manifest="./agent.json")
def my_node(state: dict) -> dict:
    return {"result": "success"}
```

**CrewAI:**

```python
from opensurity.wrappers.crewai import TrustedAgent

analyst = TrustedAgent(
    manifest="./agent.json",
    role="Data Analyst",
    goal="Analyze data"
)
```

**AutoGen:**

```python
from opensurity.wrappers.autogen import TrustedAssistantAgent

agent = TrustedAssistantAgent(
    manifest="./agent.json",
    name="analyst"
)
```

## Security Properties

**Provided:**

- **Tamper-Evident Logging:** All trust events are content-addressed and hashed into an immutable chain.
- **Replay Protection:** The 5-step handshake utilizes TTL nonces stored in SQLite.
- **Identity Verification:** Signatures are verified using local HMACs or PKI based on the progressive trust tier.
- **Framework Independence:** Trust verification sits below the LLM orchestrator.

**NOT Provided:**

- Code Sandboxing (Agents can still execute arbitrary code natively).
- P2P Network Routing (It assumes standard HTTP reaches the endpoints).
- Sybil Resistance (Without an external web-of-trust, any agent can generate a new DID/UUID).

## Contributing

We welcome contributions that expand OpenSurity's capabilities! Please ensure that any PRs maintain the strictly zero-dependency core principles, adhere to the Apache 2.0 license, and include comprehensive unit tests running on mocked dependencies where optional frameworks are involved.

## License

OpenSurity is released under the Apache 2.0 License.
