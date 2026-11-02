# PRODUCTION-ARCHITECTURE

**Repository:** Hardalion ADAP (`npl-spec`)  
**Branch:** `security/adap-complete-remediation`  
**HEAD:** `1fa576a8ef4a889685d5623d67c9ae71366c8f2d`  
**Scope:** What exists in this tree today, and the production topology required around it.

This document does not invent components that are not present as code or as an explicit deployment requirement.

## Current architecture (in this repository)

The repository is a **protocol specification plus in-process reference libraries**. It is not a multi-tenant SaaS control plane.

| Package | Role |
| --- | --- |
| `packages/policy-engine` (`adap-policy`) | Deterministic policy evaluation |
| `packages/audit-verify` (`adap-receipt`) | Authorization receipt emit/verify |
| `packages/aap` (`adap`) | Authority path: signature, delegation, policy, human approval, nonce, execute callback, receipt |

### Reference execution path

```
Principal (Ed25519 key in caller directory)
    → SignedDelegation chain
        → Agent (signed Intent)
            → presentAuthority (clone + verify signatures)
            → authorizePresented (amounts, narrowing, expiry vs trusted Clock)
            → ImmutablePolicyResolver pin (URI + content hash)
            → evaluateToolCall (ALLOW | REQUIRE_HUMAN | BLOCK)
            → [REQUIRE_HUMAN] PendingStore + NonceStore.reserve
            → [approval] binding checks + markApproved
            → NonceStore.claimForExecution
            → execute(ExecutionContext)   // caller-supplied callback
            → NonceStore.consume | fail
            → Authorization Receipt (issuer key)
```

### Trust boundaries that exist today

| Boundary | Enforced by | Trust assumption |
| --- | --- | --- |
| Intent / delegation authenticity | Ed25519 verify over canonical JSON | Caller supplies a directory of public keys; those keys are operator-provisioned |
| Evaluation time | `Clock` / `systemClock`; caller `now` rejected | Gateway process clock is not agent-controlled |
| Policy document | Required `policyResolver`; URI must be pre-registered; body must match hash | Operator owns the registry; first content hash for a URI wins |
| Nested parameter integrity | Deep clone + freeze snapshot | In-process shared objects cannot mutate authorized args after snapshot |
| Single-use intent (one process) | `NonceLedger` / `MemoryAtomicNonceBackend` | Lost on restart; not cross-process |
| Single-use intent (cross-process contract) | `AsyncAtomicNonceBackend` + `SharedNonceLedger` | Only as strong as the shared store’s atomic CAS |
| Human approval binding | Intent/agent/chain/policy/rule + signature | Approver key in directory; no revocation list |
| Execution | Optional `execute` callback | **Callback runs in the same process as the library.** Credential isolation is not enforced by the library |
| Receipt | Issuer signature + semantic invariants | Proves issuer attestation of the decision body, not durable downstream commit |

### What does not exist in this repository

- Network-facing HTTP API / admin UI
- PostgreSQL (or any durable) store implementation (added in this production pass as `packages/adap-store-postgres`)
- Credential vault / broker
- Out-of-process execution gateway (added as reference gateway package in this pass)
- Identity provider / OIDC issuer
- Multi-tenant control plane
- Cloud deployment manifests tied to a specific vendor

## Target architecture (production deployment)

```
┌──────────────────────────┐
│ Agent process            │  signing key only
│ no rail credentials      │
└────────────┬─────────────┘
             │ signed intent (+ optional approval)
             ▼
┌──────────────────────────┐
│ ADAP Execution Gateway   │  trusted host clock
│  - verify path           │  policy registry (operator)
│  - SharedNonceLedger     │◄── PostgreSQL (atomic CAS)
│  - PendingStore          │◄── PostgreSQL
│  - receipt issuer        │
│  - credential broker     │◄── vault / KMS (outside repo)
└────────────┬─────────────┘
             │ ALLOW only, authorized payload hash
             ▼
┌──────────────────────────┐
│ Downstream write API     │  rail credential never leaves vault/gateway
└──────────────────────────┘
```

### Production components

| Component | Status in this pass |
| --- | --- |
| Protocol + reference path | Exists (`adap`) |
| PostgreSQL nonce/pending adapter | Implemented (`adap-store-postgres`); integration tests executed against Postgres 16 |
| SQL migrations | Implemented |
| Multi-instance concurrency tests | Implemented; run only when `ADAP_PG_URL` is available |
| Execution gateway (HTTP, least privilege) | Reference service package; enforces capability-bound POST |
| Credential broker interface | Interface + in-memory test double; real vault is external |
| Policy registry persistence | Postgres-backed registry option |
| Observability events | Structured event emitter |
| Full identity provider | Integration interfaces only; not an IdP |

## Data flows

1. **Authorize:** signed chain + intent → gateway → verify → policy → decision.
2. **Human wait:** pending row + nonce reserved; no execute.
3. **Approve:** signed approval bound to pending snapshot → claim → execute → consume.
4. **Receipt:** sealed with gateway issuer key; stored/returned to caller.

## Failure modes (fail closed)

| Failure | Required behavior |
| --- | --- |
| Invalid signature | Unauthenticated `BLOCK`; nonce not consumed |
| DB unavailable / CAS error | No execute; structured `BLOCK` / thrown store error treated as fail-closed |
| Concurrent claim | One winner; loser `nonce_in_flight_or_used` |
| Process crash after claim, before consume | Nonce remains in-flight/failed; retry needs new intent |
| Executor throw, timeout, or cancel after dispatch | Decision stays `ALLOW`; `executed: false`; `outcome: unknown`; nonce `failed` or left in flight. Not a claim that no side effect occurred |
| Connection capacity exhausted | HTTP 503 before `executeAuthorized`; `executed: false`; `executionState: not_dispatched` |
| Process crash after dispatch | No receipt; nonce stays in flight; a retry of the same intent does not dispatch |
| Executor return then seal failure | `executed: true`; `executionHash: unhashable` possible; nonce consumed |
| Policy URI unknown | `BLOCK` |
| Caller `now` | Rejected |

## Security assumptions (deployment)

1. Agents cannot reach the downstream write URL with a rail credential.
2. All gateway instances share one PostgreSQL for nonces and pending approvals.
3. Policy documents are registered by operators before traffic is accepted.
4. Gateway clock is NTP-synced host time (zero protocol skew tolerance).
5. Approver and agent public keys are provisioned out of band.
6. Vault/KMS holds rail credentials; the gateway fetches short-lived secrets or signs vault-side.

## Claim ceiling

| Layer | May claim |
| --- | --- |
| Protocol | Narrowing, binding, amount/target domains when inputs are validated |
| Reference library | In-process fail-closed path with tested regressions |
| Postgres adapter | Cross-process exclusion **when** integration tests against real PostgreSQL pass |
| Deployment | No bypass only if network + credentials match the topology above |

A green unit suite alone does not prove distributed replay protection or credential isolation.
