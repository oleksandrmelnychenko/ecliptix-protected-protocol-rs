# Security

## Reporting vulnerabilities

Please report security-sensitive issues privately (e.g. to the maintainers) rather than in public issue trackers.

## Design trade-offs and obligations

The protocol is designed for production use with clear cryptographic guarantees. The following are intentional trade-offs or application-layer obligations that auditors and integrators should be aware of.

### Sealed state anti-rollback (external counter)

Sealed session state is bound to an **external monotonic counter** in AAD. The **application must**:

1. Use a strictly increasing `external_counter` for each `export_sealed_state` (e.g. from persistent storage).
2. Persist the last accepted counter and pass it as `min_external_counter` when calling `from_sealed_state`.
3. After a successful import, persist the sealed blob’s `external_counter` (e.g. via `sealed_state_external_counter`) for the next import check.

If the application does not enforce this, an attacker could replace the current state with an older sealed snapshot; the HMAC is valid for that snapshot, so the protocol alone cannot distinguish it. See `export_sealed_state` / `from_sealed_state` doc comments in `src/protocol/session.rs`.

### Disappearing messages (TTL)

Expiry is enforced as: `sent_timestamp + ttl_seconds > recipient SystemTime::now()`. Thus:

- A recipient who can set their system clock backward can read “disappeared” messages indefinitely.
- A sender can backdate `sent_timestamp` so that messages expire before being read, or set a far-future timestamp for a de facto infinite TTL.

This is a fundamental limitation of any disappearing-message design without a trusted time source. The protocol provides the check; the environment (clock trust) is the integrator’s responsibility.

### Group protocol: post-compromise security per epoch

Group messages use a **sender key chain** (symmetric hash ratchet). Unlike 1:1 sessions, where each direction change runs a full X25519 + Kyber ratchet, group sender keys provide **forward secrecy** along the chain but **post-compromise security only on epoch advancement** (Commit). If a sender’s chain is compromised, all subsequent messages from that sender until the next epoch can be decrypted until a new Commit is processed. This is the same trade-off as in Signal groups and MLS (O(1) encrypt/decrypt vs per-message PCS).

### 1:1 ratchet: PCS on direction change

Post-compromise security is triggered on **direction change** (and when the message chain is exhausted). If one party sends many messages in a row without a reply (e.g. 999 messages), they all share the same ratchet epoch. Compromise of a chain key in the middle would expose subsequent messages in that batch. This matches the Signal Protocol; “per-ratchet” PQ protection is per ratchet step, not per individual message.

### Padding and traffic analysis

Payloads are padded to **64-byte blocks** (ISO/IEC 7816-4 style). Ciphertext length therefore reveals plaintext length up to a 64-byte granularity (e.g. short text vs file vs image, or language-length distributions). Stronger traffic-analysis resistance would require fixed-size cells or padding to a large fixed maximum, at a bandwidth/storage cost the protocol does not impose by default.
