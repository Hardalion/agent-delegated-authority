# Signed intent

An intent is a signed attempt by an agent.

| Field | Meaning |
| --- | --- |
| `actor` | Agent id. Opaque. Implementation-defined |
| `delegation_chain` | Grants this attempt relies on |
| `action` | What is attempted |
| `target` | Where it is attempted |
| `parameters` | Arguments for the action |
| `nonce` | One-time binding against replay |
| `issued_at`, `expires_at` | Lifetime |

The signature covers the unsigned intent. Verification of the chain and the intent happens before a nonce is consumed. An unauthenticated failure does not consume the nonce.

A repeated nonce after an authenticated decision is a replay and does not execute.

## Reference

`packages/aap/src/protocol.ts`, `packages/aap/src/path.ts`, `packages/aap/src/agents.test.ts`.
