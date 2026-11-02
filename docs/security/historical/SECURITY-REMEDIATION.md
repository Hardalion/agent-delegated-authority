> **Historical snapshot.** This file records an earlier audit or local drill. It is not the current state of `main`.
> Notes that name `1fa576a` or `security/adap-complete-remediation` describe that earlier tree.
> Current status: [Security status](../status.md).

# SECURITY-REMEDIATION

**Repository:** Hardalion/agent-delegated-authority (`npl-spec` nest)  
**Audited revision:** `1fa576a8ef4a889685d5623d67c9ae71366c8f2d`  
**Remediation branch:** `security/adap-complete-remediation`  
**Assessment PDFs:** Not present in the workspace; remediation followed the mandatory finding list in the mission brief.

## Summary

All reported findings ADAP-001 through ADAP-011 were reproduced (where applicable), fixed in the reference implementation and specs, and covered by permanent regression tests. Fixes fail closed. No security check was removed to obtain a green suite.

## Findings

### ADAP-001 — Human approval policy substitution (High) — FIXED

**Root cause:** `runAuthorityPath` re-evaluated whatever `policy` object the caller supplied. A pending `REQUIRE_HUMAN` could be resumed with a permissive policy (same URI) and reach the executor without a valid human approval.

**Fix:**
- `PendingAuthorizationStore` binds intent hash, principal, agent, chain hash, policy URI/content hash/version/name, rule id, decision, expiry, nonce.
- Continuation requires that store + cryptographically verified approval bound to intent, agent, chain hash, and policy content hash.
- Pending nonces cannot continue without approval.
- `ImmutablePolicyResolver` prefers pre-registered URI pins so caller-supplied policy objects are not authoritative.
- Without a resolver, continuation requires exact policy content hash match.

### ADAP-002 — Object-valued nonce replay (High) — FIXED

**Root cause:** Nonce ledger accepted non-string keys; object identity allowed replay after independent JSON parses.

**Fix:** `assertValidNonce` requires `[A-Za-z0-9._~-]{1,128}` before every ledger operation. Objects/arrays/numbers/null rejected. Guarantees documented (in-memory vs distributed).

### ADAP-003 — Non-finite numeric values (Medium) — FIXED

**Root cause:** `amount > bound` is false for `NaN` and `-Infinity`, bypassing caps.

**Fix:** Canonical amount domain: non-negative safe integers (minor units). Reject NaN, ±Infinity, non-integers, negatives, unsafe magnitudes before authorization.

### ADAP-004 — Prototype pollution / signature-policy mismatch (High) — FIXED

**Root cause:** Canonicalization assigned `__proto__` keys onto ordinary objects; inherited properties could influence evaluation without being covered by the signature.

**Fix:** Canonical JSON uses null-prototype intermediates, rejects `__proto__` / `constructor` / `prototype`, rejects non-plain prototypes. Constraint/parameter normalization uses own-property data-only objects. Policy path resolution uses `hasOwn`.

### ADAP-005 — Inherited delegation constraints (Medium) — FIXED

**Root cause:** Narrowing used prototype-aware `in` checks; terminal enforcement used `Object.entries` (own only).

**Fix:** Normalize constraints to own-property maps before narrowing and terminal checks. Reject non-plain constraint objects. Missing own constraints fail closed.

### ADAP-006 — Empty actor / targetAgents bypass (Low) — FIXED

**Root cause:** Empty `agentRole` was treated as “unscoped” (`if (!agentRole) return true`).

**Fix:** Empty/whitespace identities rejected. Empty `agentRole` fails `targetAgents` scope. Schema rejects empty `targetAgents` entries.

### ADAP-007 — Missing required intent fields (Medium) — FIXED

**Root cause:** TypeScript types without strict runtime schema at the authority boundary.

**Fix:** Central `runtime-validate.ts` validates signed intents, delegations, approvals, nonces, identities, timestamps, parameters.

### ADAP-008 — Caller-controlled clock (Likely) — FIXED (reference boundary)

**Root cause:** Evaluation time was an untyped caller `Date` with no clock abstraction or documentation separating trusted time from request fields.

**Fix:** `Clock` / `FixedClock` / `systemClock` / `resolveTrustedNow`. Spec states production must not feed agent request bodies into the trusted clock. Expiry still checked against that trusted instant.

### ADAP-009 — Undefined amount domain — FIXED (spec + code)

Defined in `spec/amounts-and-targets.md` and `packages/aap/src/amount.ts`. Spec, implementation, and tests aligned.

### ADAP-010 — Target and currency normalization — FIXED (spec + code)

Canonical rules for targets and currency; ambiguous forms rejected rather than broadened. See `spec/amounts-and-targets.md`.

### ADAP-011 — Receipt verifier semantic inconsistency (Medium) — FIXED

**Root cause:** Structural verification did not enforce action/outcome/execution cross-field invariants.

**Fix:** `validateSemanticInvariants` in `adap-receipt`. Contradictory combinations fail closed.

## Breaking changes

Human approval payload now requires `agent_id`, `delegation_chain_hash`, and `policy_content_hash` (optional `matched_rule_id`).  
`REQUIRE_HUMAN` requires a `PendingAuthorizationStore` on the authority path.

## Remaining limitations (deployment)

- In-memory nonce and pending stores are process-local.
- Executor bypass if the agent holds downstream credentials (out of process gateway required).
- Cumulative spend is not tracked.
- Key provisioning / rotation directories are implementation-defined.
- Receipt `executed=true` is an issuer attestation, not independent observation of an external system.

## Additional review notes

Reviewed signature coverage, canonical JSON, intent/delegation hashing, approval binding, replay, TOCTOU around exclusive nonce claim before `await execute`, and receipt overclaim. No claim is made beyond what the reference path and tests demonstrate.
