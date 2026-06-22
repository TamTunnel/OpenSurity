# Security Policy

OpenSurity v0.1 provides specific trust mechanisms designed for local development and direct decentralized handshakes. Understanding the boundaries of the prototype is critical.

## What OpenSurity v0.1 Provides

- **Tamper-evident behavioral history**: All trust events are uniquely content-addressed and linked via an immutable SHA-256 chain.
- **Cryptographic agent identity**: Identity is strictly enforced at all trust boundaries. Operations require HMAC-SHA256 signatures at Level 1, and W3C DID:key Ed25519 signatures at Level 2.
- **Replay attack prevention**: The 5-step trust handshake utilizes a non-deterministic TTL nonce verification system stored locally.
- **Key isolation**: Cryptographic keys are isolated dynamically, stored on disk with `0o600` permissions, and are never exposed inside manifests or state representations.

## What OpenSurity v0.1 Does NOT Provide

- **End-to-end encryption of task payloads**: We assume TLS is handled securely at the transport layer by the application environment.
- **Zero-knowledge proofs**: L3 identity (ZK-SNARK proofs) is designated for the future roadmap.
- **Post-quantum signature security**: Algorithmic upgrades like ML-DSA-65 are part of the future roadmap.
- **Decentralized key revocation**: There is no CRL or OCSP-equivalent revocation mechanism implemented in v0.
- **Protection against a compromised agent runtime environment**: OpenSurity intercepts communication at the framework level to establish trust, but agents inherently still execute arbitrary native code. Sandboxing is left strictly to the host environment.
