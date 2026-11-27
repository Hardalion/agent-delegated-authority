# Changelog

## 0.2.0 — 2026-11-27

First npm release of `adap-receipt`, `adap-policy`, `adap-core`, `adap-store-postgres`, and `adap-gateway`. These are reference packages. They are not a hosted authority service. npm rejected the unscoped name `adap` as too similar to existing package names, so the reference authority path is published as `adap-core`.

Breaking relative to the `v0.1.0` git tag: human-approval payloads bind `agent_id`, `delegation_chain_hash`, and `policy_content_hash`. Signed objects may use `adap: 0.2` envelopes, and a chain that mixes legacy and `0.2` objects is rejected. Canonical JSON follows RFC 8785, so hashes that covered integer-like keys under the old order must be re-issued. The policy schema accepts `ALLOW`, `BLOCK`, and `REQUIRE_HUMAN`. `DEFER` and `SIMULATE` are rejected on new policy documents. The reference gateway no longer defaults `unsafeDevAllowUnconfiguredChecks` to true. `receiptId` is no longer derived only from the intent hash and the decision.

### Added

- Authorization receipts for a pin-checked call bind `execution.toolDefinitionHash`. On `ALLOW` and `REQUIRE_HUMAN` that value equals the grant's `tool_definition_hash`. `verifyReceiptMcpToolBinding` checks it offline against the tool definition (#51).
- `adap: 0.2` signed-object envelopes, actor-scoped nonces, optional receipt hash chains, and cumulative ceilings (`cumulative_max_amount`, `cumulative_<field>`) charged on a spend ledger before execution.
- Reference packages `adap-gateway` and `adap-store-postgres`. They are not required by the protocol.

### Fixed

- A missing path does not match inside `in` or `.contains()`. An empty needle does not match every string (#63, #69).
- Each emission gets its own `receiptId`, so two refusals of one intent no longer fail `verifyReceiptChain` as duplicates (#62, #68).
- `closed: true` with a cumulative ceiling admits the parameter that ceiling bounds. A child may lower any `cumulative_<field>` and still may not raise it (#58, #59, #67).
- Runtime, spend, and verifier edge cases from #47: unbound approval, non-finite amounts, caller-supplied time, exclusive nonce claim, and receipt semantic checks. A policy comparison that sees `NaN` or an infinity returns `BLOCK` (`amount_not_finite`).

### Security

- The reference gateway no longer defaults `unsafeDevAllowUnconfiguredChecks` to true. `createGatewayServer` requires an audience, `approvalPolicy.isHuman`, and a revocation check. Revocation is read from `adap_revoked_grants`, and a store failure is `unavailable` (`BLOCK`). Reported by Ahmed Shacker (@AS2812). Fixed in #47.
- `REQUIRE_HUMAN` requires a `PendingAuthorizationStore`. Continuation needs a signed approval bound to that intent. A caller-supplied `now` is rejected. The path uses a trusted clock.

### Docs

- In-grant prompt injection is recorded as a known gap. `pnpm attacks` prints it after the six refusals. The fixture is `examples/attacks/07-in-grant-injection.txt` (#52). The open tracking issue is #48.
- Deployment checklist for adopters (#53). npm quickstart in `README.md`.

### Known limitations

- **#65, targeted for v0.2.1.** A gateway throw before the downstream call (execution-state persistence, canonicalization mismatch, or broker rejection) is still signed as `ALLOW` with `outcome: unknown`. The lowercase action rule can also refuse a camelCase MCP tool name such as `getCustomer` on that path.
- **#64.** A missing path makes `!=` false. That is the rule in `spec/deterministic-evaluation.md`. A `BLOCK` condition such as `args.currency != 'EUR'` does not fire when `currency` is absent, so a later matching rule can `ALLOW`. This release does not change that comparison.
- **#48 / #52.** Prompt injection that stays inside the grant is `ALLOW`. The receipt does not record which input caused the intent. `THREAT_MODEL.md` states this limit.

## Unreleased archive

The notes below were the pre-release log. The `0.2.0` sections above are the release text. The detail here is unchanged history, not a second set of claims.

### Security remediation (#19, #3, #20, #21)

- **#19 — Signed-object versioning:** Introduces `adap: 0.2` envelopes with domain-separated preimage `ADAP/0.2/<typ>\0` + JCS of `{ adap, typ, alg, kid, payload }` for delegations, intents, and approvals. Legacy unversioned objects keep v0.1 constraint semantics (`max_amount` ceiling; other keys including `max_quantity` exact-match). Generic `max_<field>` ceilings apply only under the versioned `ceilings-v1` profile. Authority directory is keyed by `(identityId, kid)` with rotation and revocation. Delegation narrowing, intents, and human approvals are **profile-consistent**: mixed legacy/0.2 chains and cross-profile approvals are rejected. See `spec/signed-objects.md`.
- **#3 — RFC 8785 Python/JS parity:** Independent Python verifier coerces JSON numbers through IEEE-754 binary64 / ECMAScript NumberToString. Shared vectors cover `2**53±1`, large integers, exponents, negative zero, non-BMP keys. Both implementations must agree on canonical strings.
- **#20 — Actor-scoped nonces:** Ledger and PostgreSQL store key nonce state by `(actor_id, nonce)` from the verified intent. Migration `003_actor_nonce_and_pending.sql` is additive. Legacy rows with `actor_id = ''` are global tombstones that block reuse by every actor. New nonces require ≥128 bits CSPRNG entropy (`generateSecureNonce`).
- **#21 — Human DENY and approval queue:** Signed `decision: APPROVE | DENY`. DENY marks pending `declined`, retires the nonce, emits a declined receipt, never executes. Concurrent pending approvals capped per `(principal_id, agent_id)` (default 5) with atomic PostgreSQL enforcement (`approval_queue_full`).

### Backlog consolidation

Recovered PR #12 onto `main` (canonical JSON, `max_<field>`, executable `DEFER`/`SIMULATE` removal, fail-closed evaluator, execution-state reporting, Python verifier). Receipt emitter requires a real signer; demo placeholders never verify as evidence (#15). Ported Vault HTTPS/origin hardening (#2), CLI/policy-pin tests (#17), policy-only `McpToolGate` (#14), and retained #5 fixtures. Spec adds MCP binding claim levels, root/revocation/approval/policy-selection requirements, optional fail-closed hooks, conformance vectors, and README clarity vs Nexus / hackathon gate. Cumulative multi-turn budgets remain non-normative (issue #13).

### Verified issues 3, 4, 6, and 7

Canonical JSON now follows RFC 8785. Integer-like object keys are lexicographic. `examples/receipt.json` keeps content hash `35a2f27d1d11b306fbbfa81d0345afe66db6c9087d760eec7f20644744f2511c`. Hashes that covered integer-like keys under the old numeric order must be re-issued.

`max_<field>` constraints are ceilings on `parameters.<field>`. Echoing the ceiling does not satisfy the grant.

v0.1 policy documents accept only `ALLOW`, `BLOCK`, and `REQUIRE_HUMAN`. `DEFER` and `SIMULATE` stay valid on already issued receipts and are rejected by the policy schema. The protocol version stays 0.1 because those actions were never executable.

The policy evaluator blocks unexpected condition failures and non-numeric ordered comparisons instead of throwing or coercing. Nested property paths resolve to arbitrary depth on own properties only. `defaultAction: ALLOW` remains an explicit configuration. The gateway refuses a non-canonical action instead of executing a folded one, and reports `executionStatePersistence` when a state callback fails after a downstream call. `confirmed` is only used when every callback returns `'confirmed'` after a durable write. A callback that was never called is `not_attempted`. A callback that merely returns is `callback_returned`. The independent Python canonical-JSON check uses ECMAScript number formatting and runs in CI. Removing `DEFER` and `SIMULATE` from the v0.1 policy schema rejects older draft documents that named those actions. Those actions were not executable. Receipt records are unchanged.

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
