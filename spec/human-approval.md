# Human approval

Human approval is a person's decision on one intent and its authorization context.

| Field | Meaning |
| --- | --- |
| `intent_hash` | Hash of the unsigned intent being approved or denied |
| `approver_id` | Who decided (must be the delegating principal in the reference path) |
| `decision` | `APPROVE` \| `DENY` |
| `approved_at` | When, inside the intent lifetime |
| `agent_id` | Agent that presented the intent |
| `delegation_chain_hash` | Hash of the presented unsigned delegation chain |
| `policy_content_hash` | Immutable hash of the policy document that produced `REQUIRE_HUMAN` |
| `matched_rule_id` | Optional. Rule id that required human approval |

An approval or denial is bound to that full context. It does not widen a delegation and it does not override `BLOCK`.

Versioned approvals (`adap: 0.2`) also bind object version, type, algorithm, and `kid` under [signed-objects.md](./signed-objects.md).

## Decisions

### `APPROVE`

1. Verify the signature and all bindings against the active pending record.
2. Atomically mark the pending record `approved`.
3. Claim the actor-scoped nonce and invoke the executor at most once.
4. Emit a receipt with human attestation status `approved`.

### `DENY`

1. Verify the signature and all bindings against the active pending record.
2. Atomically mark the pending record `declined`.
3. Retire the corresponding actor-scoped nonce (`consumed`).
4. Emit an authenticated receipt with decision `BLOCK`, human attestation status `declined`, and the original policy rule id.
5. Never invoke the executor.
6. Reject a later `APPROVE` or a replayed `DENY` for the same pending record.

A human `DENY` is not `ALLOW` and not an unresolved `REQUIRE_HUMAN`. The receipt keeps the original policy decision distinguishable from the final human decision.

Expired pending records cannot be approved or denied as active requests.

## Pending authorization

When policy returns `REQUIRE_HUMAN`, the reference runtime persists a pending authorization record containing at least:

- intent hash, principal, agent (actor), delegation chain hash
- policy URI, policy content hash, policy version, policy name
- matched rule id, original decision `REQUIRE_HUMAN`, approval state, expiry, nonce
- expected approver id

Continuation requires:

1. The same pending record keyed by `(actor_id, nonce)` plus bindings.
2. A cryptographically verifiable `APPROVE` or `DENY` bound to those fields.
3. Policy resolution through the pinned content hash (trusted resolver or exact match). Caller-supplied policy objects are not authoritative on resume.
4. For `APPROVE`, re-evaluation of the pinned policy still yielding `REQUIRE_HUMAN` with the same rule id.

Policy substitution that turns `REQUIRE_HUMAN` into `ALLOW` without a valid bound approval is rejected. A pending nonce cannot be re-evaluated into `ALLOW` by supplying a different policy.

Duplicate approval of the same binding is rejected when a seen-approval set is configured. Expired pending records and approvals outside the intent lifetime fail closed.

## Pending approval queue limit

Operators may configure a maximum number of concurrent **active** pending approvals per `(principal_id, agent_id)`. The reference default is **5**.

Active means `approval_state = pending` and `expiry` strictly after trusted now. Approved, declined, consumed, cancelled, and expired records do not consume capacity. Expiry is applied before counting.

When the queue is full:

- the path returns deterministic `BLOCK` with rule id `approval_queue_full`
- the executor is not invoked
- no pending row is left for that request
- the nonce is not reserved

The caller cannot raise the limit through request metadata. Enforcement must be atomic across gateway instances that share the store (transaction + advisory lock in the PostgreSQL reference adapter).

## Who may approve

Approving a hash is not informed consent by itself. A conforming runtime that enforces human identity binding:

1. Requires the approver's directory entry to be of kind `human` when identity kinds are configured.
2. Rejects an approver who appears as `subject` anywhere in the presented chain, or as the intent `actor` (no self-approval through the agent key).
3. Requires the root issuer to be authorized for the namespace (see [delegation.md](./delegation.md#root-of-authority)) before treating that issuer as the sole allowed approver.
4. Binds the approval to the intent hash of a canonical rendering of action, target, and every parameter the runtime will execute.

The reference path accepts an optional `approvalPolicy` hook for steps 1–3. When absent, the path still requires `approver_id` to match the root issuer and a verifiable signature.

## Reference

`packages/aap/src/pending.ts`, `packages/aap/src/path.ts`, `packages/aap/src/human-deny-queue.test.ts`, `packages/aap/src/agents.test.ts`, `packages/aap/src/security-adversarial.test.ts`, `packages/adap-store-postgres/src/pending-store.ts`.
