# Delegation

A delegation is a signed grant from an issuer to a subject.

| Field | Meaning |
| --- | --- |
| `issuer` | Who grants the authority |
| `subject` | Who receives it |
| `capabilities` | Action and target. `delegable: false` may be used by the subject and cannot be passed on |
| `constraints` | Bounds such as `max_amount` |
| `issued_at`, `expires_at` | Lifetime |
| `parent_delegation_id` | Present when this grant narrows a parent |

## `max_amount`

`max_amount` is a **per-intent** ceiling: each signed intent's amount is checked against the terminal grant's `max_amount`. It is not a cumulative spend ledger across a delegation. This draft does not track total spending over the life of a grant. Implementations that need cumulative limits must add that outside this schema (for example in a commercial gateway) and state the semantics separately.

## Narrowing

A child cannot:

- be issued by anyone other than the parent subject
- start earlier than the parent
- expire later than the parent
- widen a target
- raise `max_amount`
- pass on a capability marked `delegable: false`

A target `resource/*` covers `resource/example`. It does not cover a deeper path.

## Reference

`packages/aap/src/validate.ts` and `packages/aap/src/validate.test.ts`.
