# Human approval

Human approval is a person's decision on one intent.

| Field | Meaning |
| --- | --- |
| `intent_hash` | Hash of the unsigned intent being approved |
| `approver_id` | Who decided |
| `decision` | `APPROVE` or `DECLINE` |
| `approved_at` | When, inside the intent lifetime |

An approval is bound to that intent hash. It does not widen a delegation and it does not override `BLOCK`.

While approval is pending, nothing executes. After a valid approval, the receipt action may become `ALLOW` and `human.status` is `approved`. The original policy `ruleId` stays on the receipt. Where a person reviews the request is implementation-defined.

## Reference

`packages/aap/src/agents.test.ts` (pending apply, then approval).
