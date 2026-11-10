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

## Who may approve (proposed)

> Status: proposed in review. Not enforced by the reference path at `bc5ae76`.

The reference path accepts an approval when `approver_id` equals `chain[0].issuer`. Combined with an unconstrained root (see [delegation.md](./delegation.md#root-of-authority-proposed)), an agent can issue its own root, receive `REQUIRE_HUMAN`, sign the approval itself, and execute. The resulting receipt says `human.status: approved`.

A conforming runtime:

1. Requires the approver's directory entry to be of kind `human`.
2. Rejects an approver who appears as `subject` anywhere in the presented chain, or as the intent `actor`.
3. Requires the root issuer to be authorized for the namespace (root of authority) before treating it as the approver.
4. Defines what the approver was shown. Approving a hash is not informed consent. The approval binds the hash of a canonical, human-readable rendering of the intent (action, target, every parameter), and the runtime renders exactly that.

## Reference

`packages/aap/src/pending.ts`, `packages/aap/src/path.ts`, `packages/aap/src/agents.test.ts`, `packages/aap/src/security-adversarial.test.ts`.
