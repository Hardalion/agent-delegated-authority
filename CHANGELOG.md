# Changelog

## Unreleased

### Sync: hardened main into hackathon participants

Merges security-hardened ADAP from `main` into the public participant branch while preserving hackathon quickstart, guides, console, sandbox APIs, and examples.

### Security remediation (#19, #3, #20, #21)

- **#19 — Signed-object versioning:** Introduces `adap: 0.2` envelopes with domain-separated preimage `ADAP/0.2/<typ>\0` + JCS of `{ adap, typ, alg, kid, payload }` for delegations, intents, and approvals. Legacy unversioned objects keep v0.1 constraint semantics (`max_amount` ceiling; other keys including `max_quantity` exact-match). Generic `max_<field>` ceilings apply only under the versioned `ceilings-v1` profile. Authority directory is keyed by `(identityId, kid)` with rotation and revocation. Delegation narrowing, intents, and human approvals are **profile-consistent**: mixed legacy/0.2 chains and cross-profile approvals are rejected. See `spec/signed-objects.md`.
- **#3 — RFC 8785 Python/JS parity:** Independent Python verifier coerces JSON numbers through IEEE-754 binary64 / ECMAScript NumberToString. Shared vectors cover `2**53±1`, large integers, exponents, negative zero, non-BMP keys. Both implementations must agree on canonical strings.
- **#20 — Actor-scoped nonces:** Ledger and PostgreSQL store key nonce state by `(actor_id, nonce)` from the verified intent. Migration `003_actor_nonce_and_pending.sql` is additive. Legacy rows with `actor_id = ''` are global tombstones that block reuse by every actor. New nonces require ≥128 bits CSPRNG entropy (`generateSecureNonce`).
- **#21 — Human DENY and approval queue:** Signed `decision: APPROVE | DENY`. DENY marks pending `declined`, retires the nonce, emits a declined receipt, never executes. Concurrent pending approvals capped per `(principal_id, agent_id)` (default 5) with atomic PostgreSQL enforcement (`approval_queue_full`).

### Backlog consolidation

Recovered PR #12 onto `main` (canonical JSON, `max_<field>`, executable `DEFER`/`SIMULATE` removal, fail-closed evaluator, execution-state reporting, Python verifier). Receipt emitter requires a real signer; demo placeholders never verify as evidence (#15). Ported Vault HTTPS/origin hardening (#2), CLI/policy-pin tests (#17), policy-only `McpToolGate` (#14), and retained #5 fixtures. Spec adds MCP binding claim levels, root/revocation/approval/policy-selection requirements, optional fail-closed hooks, conformance vectors, and README clarity vs Nexus / hackathon gate. Cumulative multi-turn budgets remain non-normative (issue #13).

### Verified issues 3, 4, 6, and 7

Canonical JSON now follows RFC 8785. Integer-like object keys are lexicographic. `examples/receipt.json` keeps content hash `35a2f27d1d11b306fbbfa81d0345afe66db6c9087d760eec7f20644744f2511c`. Hashes that covered integer-like keys under the old numeric order must be re-issued.

`max_<field>` constraints are ceilings on `parameters.<field>` under signed-object 0.2. Legacy v0.1 keeps exact-match for non-amount `max_*` keys.

v0.1 policy documents accept only `ALLOW`, `BLOCK`, and `REQUIRE_HUMAN`. `DEFER` and `SIMULATE` stay valid on already issued receipts and are rejected by the policy schema. The protocol version stays 0.1 because those actions were never executable.

The policy evaluator blocks unexpected condition failures and non-numeric ordered comparisons instead of throwing or coercing. Nested property paths resolve to arbitrary depth on own properties only. `defaultAction: ALLOW` remains an explicit configuration. The gateway refuses a non-canonical action instead of executing a folded one, and reports `executionStatePersistence` when a state callback fails after a downstream call. `confirmed` is only used when every callback returns `'confirmed'` after a durable write. A callback that was never called is `not_attempted`. A callback that merely returns is `callback_returned`. The independent Python canonical-JSON check uses ECMAScript number formatting and runs in CI. Removing `DEFER` and `SIMULATE` from the v0.1 policy schema rejects older draft documents that named those actions. Those actions were not executable. Receipt records are unchanged.

### Reference gateway and store

`adap-gateway` and `adap-store-postgres` are reference packages in this repository. They are not a protocol requirement and not a production deployment. The gateway's `executionState: unknown` means the downstream result was not observed. The authority path still reports `executed: true` because the executor callback returned, and the nonce is consumed. That boolean is not confirmation that an external system committed. Local Compose validation is documented in `docs/operations/local-staging.md`. Vault in that drill is dev mode. The hackathon console remains a synthetic local sandbox (`sandbox: true`, `realMoney: false`).

### Security remediation (ADAP-001 … ADAP-011)

Runtime fail-closed fixes for human-approval policy substitution, object nonce replay, non-finite amounts, prototype/canonicalization mismatch, inherited constraint gaps, empty identity / `targetAgents` bypass, strict intent schema validation, trusted clock separation, amount/target domain norms, and receipt semantic invariants. A policy comparison that sees `NaN` or an infinity returns `BLOCK` (`amount_not_finite`) instead of falling through to `ALLOW`. A malformed intent is rejected inside `runAuthorityPath` before the executor. Caller-supplied `now` is rejected. Breaking: human approval payloads now bind `agent_id`, `delegation_chain_hash`, and `policy_content_hash`. `REQUIRE_HUMAN` requires a `PendingAuthorizationStore`. Permanent suite: `pnpm test:security`.

Exclusive nonce claim before execution (`pending` → `consumed` | `failed`). Concurrent reuse is `BLOCK` (`nonce_in_flight_or_used`). The reference ledger is in memory; the spec states the shared-store requirement and at-most-once behavior after a crash. Optional receipt fields `sequence` and `prevReceiptHash`, checked by `verifyReceiptChain`, which detects gaps and reordering but not a dropped tail. Docs clarify `max_amount` is per-intent (not cumulative) and that keeping credentials out of the agent process is a deployment property.

Dependencies: `vitest` 4.1.12, `vite` 6.4.4, `zod` 4.6.6 or later, for published advisories.

The front of the README is a public draft, not a claim to be a standard. It states the question the draft answers, and what it does not replace: identity, authentication, OAuth, agent communication, and execution runtimes.

The receipt binds `policy.contentHash`, the canonical hash of the policy document that was loaded, and `execution.intentHash`, the intent presented at the execution boundary. `pnpm attacks` runs six refusals: over-delegation, privilege escalation, prompt injection, replay, expiry, and a mutated intent after approval.

The receipt is independently verifiable offline when the issuer public key is available. `adap-receipt` checks the Ed25519 signature only with `--public-key`. `examples/proof/` publishes one reference run a third party can verify with no hosted service. The receipt binds the canonical hash of the policy document.

The Authorization Receipt binds each presented delegation by hash. An agent outside the policy is `BLOCK` (`agent_not_in_scope`). An unmatched call follows `defaultAction`. `executed` records what the governing runtime reported, not an independent observation of an external system. `pnpm demo` runs a synthetic principal-to-agent-to-agent purchase bound: route `ATH-LON`, maximum 500 EUR, a raised child grant refused, and instruction text that does not move the bound.

## 0.1.0 — 2026-10-07

Public Draft of the Agent Delegated Authority Protocol (ADAP).

ADAP is an open protocol for delegated authority between AI agents. An agent should never receive more authority than the principal intended to delegate.

This draft specifies delegation, intent, policy, authorization, and the Authorization Receipt. The reference implementation is in this repository. Ed25519, SHA-256, and canonical JSON are the reference profile. They are not required by the protocol.

The packages `adap`, `adap-policy`, and `adap-receipt` are not currently published to npm in this draft. Clone the repository and build it.
