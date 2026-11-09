# Changelog

## Unreleased

### Verified issues 3, 4, 6, and 7

Canonical JSON now follows RFC 8785. Integer-like object keys are lexicographic. `examples/receipt.json` keeps content hash `35a2f27d1d11b306fbbfa81d0345afe66db6c9087d760eec7f20644744f2511c`. Hashes that covered integer-like keys under the old numeric order must be re-issued.

`max_<field>` constraints are ceilings on `parameters.<field>`. Echoing the ceiling does not satisfy the grant.

v0.1 policy documents accept only `ALLOW`, `BLOCK`, and `REQUIRE_HUMAN`. `DEFER` and `SIMULATE` stay valid on already issued receipts and are rejected by the policy schema. The protocol version stays 0.1 because those actions were never executable.

The policy evaluator blocks unexpected condition failures and non-numeric ordered comparisons instead of throwing or coercing. Nested property paths resolve to arbitrary depth on own properties only. `defaultAction: ALLOW` remains an explicit configuration. The gateway refuses a non-canonical action instead of executing a folded one, and reports `executionStatePersistence` when a state callback fails after a downstream call.

### Reference gateway and store

`adap-gateway` and `adap-store-postgres` are reference packages in this repository. They are not a protocol requirement and not a production deployment. The gateway's `executionState: unknown` means the downstream result was not observed. The authority path still reports `executed: true` because the executor callback returned, and the nonce is consumed. That boolean is not confirmation that an external system committed. Local Compose validation is documented in `docs/operations/local-staging.md`. Vault in that drill is dev mode.

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
