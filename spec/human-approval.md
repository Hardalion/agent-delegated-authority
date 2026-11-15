# Human approval

Human approval is a person's decision on one intent and its authorization context.

| Field | Meaning |
| --- | --- |
| `intent_hash` | Hash of the unsigned intent being approved |
| `approver_id` | Who decided (must be the delegating principal in the reference path) |
| `decision` | `APPROVE` (decline is modeled by withholding approval) |
| `approved_at` | When, inside the intent lifetime |
| `agent_id` | Agent that presented the intent |
| `delegation_chain_hash` | Hash of the presented unsigned delegation chain |
| `policy_content_hash` | Immutable hash of the policy document that produced `REQUIRE_HUMAN` |
| `matched_rule_id` | Optional. Rule id that required human approval |

An approval is bound to that full context. It does not widen a delegation and it does not override `BLOCK`.

## Pending authorization

When policy returns `REQUIRE_HUMAN`, the reference runtime persists a pending authorization record containing at least:

- intent hash, principal, agent, delegation chain hash
- policy URI, policy content hash, policy version, policy name
- matched rule id, original decision `REQUIRE_HUMAN`, approval state, expiry, nonce

Continuation requires:

1. The same pending record (nonce + bindings).
2. A cryptographically verifiable approval bound to those fields.
3. Policy resolution through the pinned content hash (trusted resolver or exact match). Caller-supplied policy objects are not authoritative on resume.
4. Re-evaluation of the pinned policy still yielding `REQUIRE_HUMAN` with the same rule id.

Policy substitution that turns `REQUIRE_HUMAN` into `ALLOW` without a valid bound approval is rejected. A pending nonce cannot be re-evaluated into `ALLOW` by supplying a different policy.

Duplicate approval of the same binding is rejected when a seen-approval set is configured. Expired pending records and approvals outside the intent lifetime fail closed.

## Reference

`packages/aap/src/pending.ts`, `packages/aap/src/path.ts`, `packages/aap/src/agents.test.ts`, `packages/aap/src/security-adversarial.test.ts`.
