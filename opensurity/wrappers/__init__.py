"""
OpenSurity SDK Wrappers.

These modules provide framework-agnostic wrappers that intercept agent execution,
verify delegating agent identity, and log TrustEvents to the local store.

Modules:
- `langgraph`: Provides the `@trust_node` decorator for LangGraph nodes.
- `crewai`: Provides the `TrustedAgent` base class for CrewAI agents.
- `autogen`: Provides the `TrustedAssistantAgent` base class for AutoGen agents.

Note: Import these modules individually to avoid optional dependency ImportErrors
for frameworks you are not using.
Example:
    from opensurity.wrappers.crewai import TrustedAgent
"""
