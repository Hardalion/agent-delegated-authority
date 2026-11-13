# Signed intent

An intent is a signed attempt by an agent.

| Field | Meaning |
| --- | --- |
| `intent_id` | Intent identifier (non-empty string) |
| `actor` | Agent id. Opaque non-empty string. Empty and whitespace-only ids are rejected |
| `delegation_chain` | Grants this attempt relies on (non-empty) |
| `action` | What is attempted. Exact string. The authority check does not case-fold it. A gateway that requires a canonical action must refuse a non-canonical value instead of executing a folded one |
| `target` | Where it is attempted (see [amounts-and-targets.md](amounts-and-targets.md)) |
| `parameters` | Arguments for the action (plain data object; dangerous keys rejected) |
| `nonce` | One-time binding against replay. Non-empty string matching `[A-Za-z0-9._~-]{1,128}`. Objects, arrays, numbers, booleans, and null are rejected |
| `issued_at`, `expires_at` | Lifetime (ISO-8601 UTC) |
| `signature` | Signature over the unsigned intent (legacy) or the domain-separated envelope ([signed-objects.md](./signed-objects.md)) |

The signature covers the unsigned intent (legacy) or the versioned envelope. Runtime schema validation runs before authorization. Malformed intents must never reach the executor.

Verification of the chain and the intent happens before a nonce is consumed. An unauthenticated failure does not consume the nonce.

Nonce state is keyed by `(actor_id, nonce)`, where `actor_id` is the cryptographically verified intent `actor`. Two agents may reuse the same nonce string independently. One agent cannot retire another agent's nonce.

Newly generated nonces MUST contain at least 128 bits of cryptographically secure randomness (`generateSecureNonce` in the reference implementation). Deterministic fixture nonces are test-only.

A repeated `(actor, nonce)` after an authenticated decision is a replay and does not execute. The reference nonce ledger is process-local unless a shared atomic store is configured by the deployment.

Trusted evaluation time comes from the runtime clock (or a test `FixedClock`). Intent timestamps are untrusted request data checked against that trusted now. Callers must not feed agent-controlled request fields into the trusted clock.

## Reference

`packages/aap/src/protocol.ts`, `packages/aap/src/runtime-validate.ts`, `packages/aap/src/path.ts`, `packages/aap/src/security-adversarial.test.ts`.
