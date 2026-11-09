# Threat model

**Status:** Public Draft (v0.1) — final hardening baseline.
**License:** Apache 2.0

ADAP authorization correctness is not complete agent security.

A correct decision means the presented delegation, intent, and policy authorized or refused the action. It does not mean the surrounding system is safe.

## Layers of guarantee

| Layer | What it covers |
| --- | --- |
| Protocol | Normative rules in `spec/`: narrowing, intent binding, human approval context, receipt semantics, amount/target domains, fail-closed policy defaults and identity |
| Reference implementation | `packages/aap`, `adap-policy`, `adap-receipt` enforce those rules at runtime with fail-closed validation |
| Deployment | Network placement, credential isolation, shared atomic nonce/pending stores, key management, trusted clock, operator-owned policy registry |

## What the reference path stops

- Over-delegation. A child cannot raise the parent's bound.
- Privilege escalation. A capability marked `delegable: false` cannot be passed on.
- Replay inside one store. A string nonce is validated then claimed exclusively before execution; object-valued nonces are rejected.
- Unauthorized execution. `BLOCK` and an unresolved `REQUIRE_HUMAN` do not call the executor. Only `ALLOW` (including post-approval) reaches the executor.
- Policy substitution on human-wait. A pending `REQUIRE_HUMAN` is bound to immutable policy content hash, intent, principal, agent, chain, and URI. Continuation cannot become `ALLOW` by supplying a different policy.
- Prompt injection that tries to raise the bound. Instruction text is not a constraint.
- Non-finite / unsafe amounts. `NaN`, ±Infinity, and non-safe-integer amounts are rejected. A policy comparison that sees a non-finite number returns `BLOCK` (`amount_not_finite`) and does not fall through to `defaultAction: ALLOW`.
- Prototype-key influence. Dangerous keys and non-plain prototypes are rejected at canonicalization and constraint normalization.
- Nested parameter mutation after authorization. Execution and the receipt use deep copies of the verified snapshot.
- Unauthenticated nonce griefing. Signature verification happens before any nonce reserve/claim/consume.
- Canonicalization exceptions escaping the public API. Malformed input returns a structured `BLOCK` without a throw.
- Caller-controlled time. A `now` field on the authority-path input is rejected. Expiry uses a trusted `Clock`.
- Missing identity or policy default. Omitted `agentRole` and missing `defaultAction` fail closed to `BLOCK`.
- Ambiguous resource forms. Dot segments, empty segments, percent-encoding, and URL-shaped targets are rejected.
- Contradictory receipts. Verifiers reject action/outcome/execution inconsistencies.

## What this draft guarantees

In the reference path:

| Threat | Result |
| --- | --- |
| Over-delegation | A child that raises `max_amount`, widens a target, outlives the parent, drops a parent **own** constraint, or is issued by anyone other than the parent subject is `BLOCK`. Rule `narrowing`. |
| Privilege escalation | A capability marked `delegable: false` cannot be passed on. |
| Unauthorized sub-agent | An action outside the granted capabilities is `BLOCK`. Rule `capability`. |
| Empty / malformed identity | Empty actor ids and empty `targetAgents` entries fail closed. Omitted or empty `agentRole` does not bypass scoped or wildcard policies. |
| Expired authority | Checked against a **trusted runtime clock**. Caller-supplied `now` is rejected. |
| Replay / concurrent reuse | Nonce must be a canonical string. Claim is exclusive (`pending` → in-flight → `consumed`/`failed`). In-memory: one process. Cross-process: requires an `AsyncAtomicNonceBackend` whose compare-and-swap is atomic in a shared store. |
| Human-approval bypass | Pending store + approval binding to intent, agent, chain hash, policy content hash, and URI. Duplicate approval keys are recorded only after signature and lifetime checks. |
| Policy substitution | Operator-owned resolver is required. Unknown URIs are not registered from the caller. Caller policy must hash to the pin. |
| Signature / policy mismatch | Canonical JSON rejects `__proto__` / `constructor` / `prototype` keys and non-plain prototypes so signed bytes match evaluated data. |
| Unauthorized execution | `BLOCK` and unresolved `REQUIRE_HUMAN` return before the executor. |
| Receipt forgery under a known issuer key | Signature + content hash cover the body. Semantic invariants reject contradictory action/outcome/execution. |
| Receipt overclaim | A valid structure does not prove downstream side effects unless `execution.executed` is true and consistent with `ALLOW`. The callback's return is what the path reports. |

## Protocol vs reference vs deployment

| Claim | Layer |
| --- | --- |
| Child grants cannot widen parent grants | Protocol + reference |
| Human approval is bound to one intent hash and policy content hash | Protocol + reference |
| Amounts are non-negative safe integers | Protocol + reference |
| Missing policy `defaultAction` is not ALLOW | Protocol + reference |
| Omitted agent identity is not in scope | Protocol + reference |
| Exclusive nonce claim across processes | Deployment (shared atomic store). Production adapter: `packages/adap-store-postgres` (`PostgresAtomicNonceBackend` + `SharedNonceLedger`). Exclusion holds only when every gateway instance shares that database. |
| Agent cannot call the write API with a rail credential | Deployment (credential isolation) |
| Wall-clock equals the evaluation clock | Deployment (gateway host clock). Tests inject `FixedClock`. |
| External system performed the side effect | Outside ADAP. Receipts attest the authority decision and the callback report. |

## Deployment boundary (credentials)

The in-process reference callback is for local testing. If the agent process holds the API credential, it can skip this path. That is outside what an in-process SDK can prevent.

A deployment that needs the boundary to hold runs the check **out of process**: a sidecar, an MCP server gateway, or a commercial enforcement gateway. The agent holds only the key it signs intents with. It holds no rail credential. The credential stays in the operator's vault, attached to a write endpoint that accepts a request only from the gateway, and only after `ALLOW`.

```
┌──────────────────┐   signed intent   ┌─────────────────────────┐
│ Agent process    │ ────────────────► │ ADAP gateway / sidecar  │
│ signing key only │                   │  verify + policy        │
│ no rail cred     │                   │  pending + nonce store  │
└──────────────────┘                   │  receipt                │
                                       └───────────┬─────────────┘
                                                   │ ALLOW only
                                                   ▼
                                       ┌─────────────────────────┐
                                       │ Operator write endpoint │
                                       │ credential in vault     │
                                       └─────────────────────────┘
```

The property holds only when the operator's network gives the agent no other route to that endpoint or credential. ADAP defines the authority semantics. `packages/adap-gateway` is a reference process for that boundary. This repository does not ship the operator's network policy, and the gateway does not enforce it by itself.

## Trust assumptions

- Human approver keys are provisioned out of band; the directory maps `approver_id` → public key.
- The policy resolver is operator-trusted. Documents are registered before requests are served. The first content hash for a URI wins; a different body for the same URI is rejected.
- Production trusted clock is the gateway host clock (or equivalent), never a field from the agent request body. The reference path applies zero skew tolerance: `issued_at <= now < expires_at`.
- Receipt verification with the issuer public key proves the issuer attested the body. It does not by itself prove an external system performed the action unless independent execution evidence is present.

## Known limitations (not claimed)

- Malicious model behavior beyond the bound.
- Compromised host or a runtime that skips this path.
- Credential isolation when the agent holds the rail credential.
- Cumulative spend across a delegation (`max_amount` is per intent).
- Distributed replay protection without a shared atomic nonce/pending store that meets `AsyncAtomicNonceBackend` (use `adap-store-postgres` or equivalent).
- Exactly-once after crash: a claim left `pending`/in-flight blocks that nonce; retry is a new intent.
- Compromised private keys.
- Identity provisioning and key rotation ceremonies (implementation-defined).
- Availability / DoS.
- Executor that returns after a partial external write and then throws: the path records `executed: false` and spends the nonce. Operators must make the write idempotent or reconcilable.
- Executor that returns a value that cannot be hashed: the path still reports `executed: true` with `executionHash: unhashable` and no receipt body. The nonce is spent.

## Gaps raised in review (proposed)

These are inside the draft's own scope and are not listed above.

| Gap | Where |
| --- | --- |
| Any directory key can issue a root delegation, and the root issuer is the required approver, so an agent can approve its own `REQUIRE_HUMAN` | [delegation.md](spec/delegation.md#root-of-authority-proposed), [human-approval.md](spec/human-approval.md#who-may-approve-proposed) |
| The caller chooses the governing policy | [policy-decision.md](spec/policy-decision.md#which-policy-governs-proposed) |
| `BLOCK` rules do not match when the compared argument is missing | [deterministic-evaluation.md](spec/deterministic-evaluation.md#missing-and-non-numeric-operands-proposed) |
| No delegation revocation | [delegation.md](spec/delegation.md#revocation-proposed) |
| Nonces are keyed by nonce alone, not by `(actor, nonce)`. Any directory identity can spend another agent's predictable nonce first | `packages/aap/src/nonce.ts` |
| The agent's intent-signing key sits in the process the model drives. A prompt-injected agent signs anything inside its bounds. A signed intent gives attribution, not proof the principal wanted it | Deployment boundary above |
| Decisions are per call. Split spending and sequences of individually allowed calls pass | [mcp-binding.md](spec/mcp-binding.md#session-state) |
| Receipt chain is not used by the reference gateway and is not tamper-evident against the issuer | [authorization-receipt.md](spec/authorization-receipt.md) §7.1 |

## Out of scope

Physical-world safety, model alignment, and business logic beyond delegation constraints and the evaluated policy.

Normative narrowing: [spec/delegation.md](spec/delegation.md). Amounts/targets: [spec/amounts-and-targets.md](spec/amounts-and-targets.md). Human approval: [spec/human-approval.md](spec/human-approval.md). Policy schema: [spec/policy-schema.md](spec/policy-schema.md). Receipts: [spec/authorization-receipt.md](spec/authorization-receipt.md). Reference path: `packages/aap/src/path.ts`, `packages/aap/src/validate.ts`, `packages/aap/src/runtime-validate.ts`, `packages/aap/src/nonce.ts`.
