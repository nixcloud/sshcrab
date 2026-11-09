# P2P UDP Service Registry & NAT Traversal Specification

**Status:** Draft  
**Version:** 0.3  
**Date:** 2026-11-09  
**Implementation:** peeroxide-dht (HyperDHT)

## 1. Purpose

This specification defines a pure peer-to-peer Rust library that enables a UDP-based service (e.g. an OpenSSH-like service running over UDP) located behind NAT to publish its current public endpoints and to accept connections from clients anywhere on the internet via UDP hole punching.

The library provides a decentralized registry in which services are identified by their SSH host key. Clients resolve a host key to one or more public IPv4/IPv6 endpoints, verify authenticity, perform hole punching, and then run the normal SSH protocol over the resulting direct UDP path.

The concrete DHT and hole-punching implementation is **peeroxide-dht** (Rust port of HyperDHT).

## 2. Goals

- Allow a UDP service behind NAT to be reachable from the public internet without manual port forwarding.
- Provide a decentralized, pure-P2P registry (no single central server of record and no permanent gateway).
- Use the service’s SSH host key as the stable DHT key / identifier.
- Store and retrieve the service’s current public IPv4 and/or IPv6 endpoints.
- Keep published entries alive through periodic refresh.
- Make UDP hole punching straightforward once both parties know each other’s public endpoints.
- Prevent unauthorized parties from publishing arbitrary endpoints under a given host key.
- Bind the SSH host key verification to the DHT lookup so that classic MITM attacks are mitigated.

## 3. Non-Goals

- Reliable stream transport or full SSH implementation (the library focuses on endpoint discovery and hole punching; the application runs its own SSH protocol over the resulting UDP path).
- Full mesh networking or arbitrary peer-to-peer data routing beyond the registry and hole-punch coordination.
- Support for TCP-only services.
- Centralized fallback registries (any bootstrap nodes are only for DHT join, not for authoritative data).
- Mandatory relay/gateway for all traffic.

## 4. Terminology

| Term | Definition |
|------|------------|
| **Host key** | Long-term SSH host public key that uniquely identifies a service. Used as the DHT key. |
| **Endpoint** | A publicly reachable socket address (`IPv4` or `IPv6` + port). |
| **Registry** | Decentralized distributed hash table (DHT) that stores signed endpoint records. Implemented by peeroxide-dht. |
| **Announcement** | Act of publishing or refreshing a signed endpoint record under a host key. |
| **Hole punching** | Coordinated exchange of UDP packets that opens NAT mappings so two peers can communicate directly. |
| **Signed record** | Endpoint data together with a signature produced by the private key corresponding to the host key. |
| **Bootstrap node** | Publicly reachable peer used only to join the DHT; not authoritative for data. |

## 5. Architecture Overview

┌─────────────┐     announce (signed by host key)   ┌──────────────────┐

│   Service   │ ──────────────────────────────────► │  peeroxide-dht   │

│ (behind NAT)│                                     │  (HyperDHT)      │

└─────────────┘                                     └──────────────────┘

▲                                                    │

│  hole-punch packets                                │ lookup by host key

│                                                    ▼

┌─────────────┐     resolve + verify signature     ┌──────────────────┐

│   Client    │ ◄────────────────────────────────── │  peeroxide-dht   │

│ (anywhere)  │                                     └──────────────────┘

└─────────────┘

│

└──► direct UDP path → normal SSH handshake

(server must present the same host key)
Text
1. The service discovers its public endpoints (via DHT peers observing its packets or lightweight probes).
2. It creates a signed record containing those endpoints and publishes it under its SSH host key via peeroxide-dht.
3. It periodically re-announces to keep the record alive.
4. A client looks up the host key, verifies the signature, and obtains the endpoints.
5. Both sides exchange UDP packets to the learned endpoints, completing hole punching (peeroxide-dht holepuncher).
6. The resulting direct UDP path is used for the normal SSH protocol. The server must present the same host key that was used for the DHT lookup; the client aborts on mismatch.

## 6. Functional Requirements

### 6.1 Registry

- **FR-1** The registry MUST be implemented as a pure peer-to-peer distributed hash table using **peeroxide-dht**.
- **FR-2** The primary key in the registry MUST be the SSH host public key (or a deterministic derivation of it).
- **FR-3** The value stored under a host key MUST be a signed record containing the service’s current public endpoints.
- **FR-4** A service MUST be able to publish and refresh its record so that the entry remains available.
- **FR-5** A client MUST be able to resolve a host key to zero or more verified public endpoints.
- **FR-6** No permanent central gateway or authoritative server is required. Only optional bootstrap nodes for initial DHT join.

### 6.2 Endpoint Discovery & Announcement

- **FR-7** A service MUST be able to discover its own public IPv4 and/or IPv6 endpoints.
- **FR-8** The published record MUST support both IPv4 and IPv6 endpoints (either or both may be present).
- **FR-9** Records MUST include a timestamp or sequence number so that newer announcements supersede older ones.
- **FR-10** The library MUST periodically refresh announcements while the service is running.

### 6.3 Connection Establishment

- **FR-11** Once a client has obtained verified endpoints for a host key, the library MUST assist in performing UDP hole punching using peeroxide-dht’s hole-punching facilities.
- **FR-12** After successful hole punching the library MUST provide the application with a usable direct UDP path.
- **FR-13** Hole punching coordination MAY use the DHT itself. No long-lived central relay is required for the common case. Optional blind-relay fallback is available in peeroxide-dht but not mandatory.
- **FR-14** After the direct path is established, the application runs its normal SSH protocol. The server MUST present the same host key that was used for the DHT lookup.

### 6.4 Identity

- **FR-15** Every service MUST possess a long-term SSH host key pair.
- **FR-16** The public half of the host key is the stable name used by clients to locate the service and is the DHT key.

## 7. Security Requirements

### 7.1 Anti-Flooding / Authenticity

- **SR-1** Every registry record MUST be cryptographically signed by the private key corresponding to the host key under which it is stored.
- **SR-2** DHT nodes MUST reject (or refuse to store) records whose signature does not verify against the claimed host key.
- **SR-3** Clients MUST verify the signature of any retrieved record before using the contained endpoints. Records that fail verification MUST be discarded.
- **SR-4** An entity that does not possess the private host key MUST NOT be able to publish a record that honest nodes and clients will accept under that host key.

### 7.2 MITM Mitigation

- **SR-5** The client MUST know the expected host key before (or independently of) the DHT lookup.
- **SR-6** After hole punching, the SSH handshake MUST present exactly that host key. Any mismatch MUST cause the client to abort.
- **SR-7** First-connection trust follows normal SSH practice (TOFU or out-of-band host-key distribution). Subsequent connections verify against the stored host key.

### 7.3 Additional Protections

- **SR-8** Records SHOULD carry a monotonic sequence number or timestamp; clients and nodes SHOULD prefer the newest valid record.
- **SR-9** Implementations SHOULD expire or deprioritize records that have not been refreshed within a configurable TTL.
- **SR-10** Optional rate limiting or storage quotas per key MAY be applied by DHT nodes.

## 8. Data Model

### 8.1 Signed Endpoint Record

SignedEndpointRecord {

host_key:        PublicKey,          // SSH host public key (DHT key)

endpoints:       Vec,    // public IPv4/IPv6 + port

sequence:        u64,                // monotonic, higher wins

timestamp:       u64,                // optional wall-clock seconds

signature:       Signature           // over the canonical encoding of the above

}
Text
- The signature MUST cover at least `host_key`, `endpoints`, and `sequence`.
- Canonical encoding MUST be deterministic.
- Implemented via peeroxide-dht mutable records / announce bound to an Ed25519 `KeyPair`.

### 8.2 DHT Key

The DHT key is the SSH host public key (or a fixed-length hash of it if the DHT key size requires it). In peeroxide-dht this is an Ed25519 public key.

## 9. Operational Considerations

- **Bootstrap**: Nodes require a small set of well-known bootstrap peers to join the DHT. These peers are not authoritative for data and are not in the data path after join. peeroxide-dht supports public HyperDHT bootstrap nodes or custom ones.
- **NAT types**: UDP hole punching is expected to succeed for full-cone, restricted-cone, and port-restricted cone NATs. Symmetric NATs may fail; peeroxide-dht’s optional blind-relay fallback may be used.
- **Keep-alive interval**: Recommended default re-announcement interval is 60–180 seconds.
- **IPv6 preference**: When both address families are available, implementations SHOULD prefer IPv6.
- **No permanent gateway**: Neither the DHT nor the hole-punch path requires a hosted gateway that proxies application traffic.

## 10. Implementation (peeroxide-dht)

The registry and hole-punching layer MUST be built on **peeroxide-dht**.

Key mapping:
- SSH host key → Ed25519 `KeyPair` / public key used as DHT identity.
- Publish via `announce` or `mutable_put` under the host key (signed).
- Lookup via the corresponding peeroxide-dht lookup / mutable get.
- Hole punching via the built-in `holepuncher` and Noise-secured connection path.
- After the direct (or optionally relayed) path is established, the UDP socket or encrypted stream is handed to the SSH layer.
- Periodic re-announce keeps the record alive.

Cryptography used by peeroxide-dht:
- Ed25519 (identity + signatures)
- Noise XX / IK (`Noise_XX_Ed25519_ChaChaPoly_BLAKE2b` and IK variant)
- ChaCha20-Poly1305 (AEAD)
- BLAKE2b (hashing / KDF)

## 11. Assumptions

- The underlying UDP service (or a thin shim) can send and receive datagrams on a known local port.
- Participating nodes can open outbound UDP connections.
- A modest number of publicly reachable DHT bootstrap nodes exist (or can be run by the operator).
- Host keys are Ed25519 (compatible with peeroxide-dht).

## 12. Open Points

- Exact wire format binding between SSH host key and peeroxide-dht key representation.
- Whether the optional blind-relay fallback is enabled by default.
- Concrete connection-racing strategy when multiple endpoints are present.
- Integration details with an existing OpenSSH-like codebase (how the punched UDP path is presented to the SSH layer).

---

# Risk Analysis

## 1. Chosen Crate: peeroxide-dht

| Aspect | Assessment |
|--------|------------|
| Maturity | Young (first releases ~2026). Wire-compatible port of the longer-lived Node.js HyperDHT/Hyperswarm stack. |
| Maintenance | Active (multiple releases, interop tests against Node.js reference). Small community so far. |
| Audit status | No public independent security audit identified. |
| Dependencies | Pure Rust crypto stack: `ed25519-dalek`, `chacha20poly1305`, `blake2`, `curve25519-dalek`, plus `libudx`. No libsodium. |
| Known issues | Inherits HyperDHT design. Public Node.js issues include unauthenticated handshake floods, missing size limits on PUT values, and some hole-punch edge cases (same-LAN + strict firewall). These are largely protocol/implementation concerns rather than crypto breaks. |
| DHT-specific risks | Classic Kademlia risks remain: Sybil attacks, eclipse attacks, routing table poisoning. HyperDHT mitigates some Sybil vectors by deriving node IDs from observed public address. Signed records protect the *content* under a given host key, but do not fully protect routing. |
| Overall risk | Medium. Suitable when clients always verify signatures and host keys, and operators accept residual DHT routing risks. |

## 2. Cryptography Used (peeroxide-dht)

| Primitive | Usage | Assessment |
|-----------|-------|------------|
| **Ed25519** (`ed25519-dalek`) | Host-key signatures, DHT identity, Noise static keys | Standard, widely audited primitive. Safe when used correctly. |
| **Noise XX / IK** | Authenticated key exchange for peer connections | Well-specified Noise patterns. Provides mutual authentication and forward secrecy. Implementation is a port; correctness relies on golden-test interop with the Node.js reference. |
| **ChaCha20-Poly1305** | AEAD for secret streams and Noise payloads | Standard, high-performance AEAD. No known practical breaks when nonces are unique. |
| **BLAKE2b** | Hashing for topics, key derivation, Noise | Secure hash. |
| **X25519** (via curve25519-dalek) | Diffie-Hellman in Noise | Standard. Port claims byte-compatibility with the reference. |

### Residual cryptographic risks

- Implementation bugs in the Noise port or secret-stream framing (mitigated by golden fixtures and live interop tests, but not a formal audit).
- Side-channel leakage in the pure-Rust crypto crates (generally well-regarded).
- No post-quantum protection by default.

## 3. Systemic Risks

| Risk | Description | Mitigation in this design |
|------|-------------|---------------------------|
| DHT Sybil / Eclipse | Attacker floods routing tables or surrounds a node | Signed records still protect content authenticity. Clients verify signatures. Running own bootstrap nodes reduces exposure. |
| Record flooding under random keys | Attacker stores garbage | Irrelevant to clients that only look up specific host keys. |
| MITM on the data path | Network attacker intercepts after hole punch | Prevented by SSH host-key verification bound to the DHT key. |
| Symmetric NAT failure | Hole punching fails | Accept failure or enable optional blind relay (end-to-end encrypted). |
| Bootstrap node compromise | Malicious bootstrap lies about peers | Only affects initial join; subsequent routing and signed records limit damage. |
| Private host-key compromise | Attacker can publish arbitrary endpoints and impersonate the SSH server | Same impact as a compromised SSH host key today. Rotate key and update clients. |

## 4. Summary Risk Posture

peeroxide-dht + signed host-key records + SSH host-key check provides strong authenticity and MITM resistance for the registry and the subsequent SSH session. Residual risk is mainly DHT routing attacks and the relative youth of the Rust port.

Operators should:
1. Always verify DHT record signatures and SSH host keys.
2. Prefer running or pinning their own bootstrap nodes.
3. Keep dependencies updated and monitor advisories.
4. Treat the private SSH host key as the root of trust.
