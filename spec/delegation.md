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

## `max_<field>` ceilings

A constraint key `max_<field>` is a per-intent ceiling on `parameters.<field>`.

| Constraint | Bounded parameter |
| --- | --- |
| `max_amount` | `amount` |
| `max_quantity` | `quantity` |
| `max_records` | `records` |

`<field>` matches `^[A-Za-z][A-Za-z0-9_]*$`. The same rule applies to every such key. The value is a canonical non-negative safe integer. The intent parameter must be present and must be less than or equal to the ceiling. Echoing the ceiling as its own parameter does not satisfy it: `{ quantity: 999, max_quantity: 5 }` is outside a grant of `max_quantity: 5`. A missing bounded parameter fails closed.

`read` and `search` may omit `amount` when the only ceiling in question is `max_amount`. That exception does not apply to other actions or to other `max_<field>` keys.

`max_amount` is not a cumulative spend ledger. This draft does not track total spending over the life of a grant. Implementations that need cumulative limits must add that outside this schema and state the semantics separately.

## Narrowing

A child cannot:

- be issued by anyone other than the parent subject
- start earlier than the parent
- expire later than the parent
- widen a target
- raise a `max_<field>` ceiling, including `max_amount` and `max_quantity` (canonical safe-integer units; see [amounts-and-targets.md](amounts-and-targets.md))
- pass on a capability marked `delegable: false`
- drop a parent constraint, including by relying on inherited / prototype properties

Constraints are normalized to own-property data-only objects before narrowing and before terminal enforcement. Prototype-bearing constraint objects are rejected. Missing own constraints are not treated as unlimited authority.

A target `resource/*` covers `resource/example`. It does not cover a deeper path.

## Root of authority

A signature from a key in a directory does not, by itself, make its holder a principal. An id-to-key map is not a root-of-authority policy.

A conforming runtime that enforces root of authority:

1. Holds an operator-owned **root-of-authority** configuration: which identities may issue a root delegation, and for which `action` / `target` namespaces.
2. Rejects a root whose issuer is not authorized for every capability it grants (`root_not_authorized`).
3. Rejects a root whose issuer is also its subject, unless the configuration explicitly allows that for the namespace.
4. Distinguishes identity kinds (`human`, `agent`, `service`) when verifying approvals and roots.

The reference path accepts an optional `rootAuthority` hook on `runAuthorityPath`. When the hook is absent, root checks are deployment-owned and out of band. When present, a failed check is fail-closed `BLOCK`.

## Revocation

A delegation is valid until `expires_at` unless revoked earlier. Key rotation withdraws every grant from that issuer; per-delegation revocation is finer-grained.

A conforming runtime that supports revocation:

1. Checks each `delegation_id` in the presented chain against an operator-owned revocation status at decision time.
2. Checks again before continuing an approved `REQUIRE_HUMAN`.
3. Treats a revoked link as `BLOCK` with rule `revoked`.
4. Fails closed when revocation status cannot be read.

The reference path accepts an optional `revocationCheck` hook. When absent, only expiry applies. When present, `revoked` and `unavailable` fail closed.

## Constraint scope

In v0.1, constraints apply to the whole terminal delegation. Parameters not named by any constraint are unbounded unless policy rules cover them. A future revision may attach constraints per capability and support `closed: true` (any unnamed parameter is `BLOCK`).

`max_<field>` ceilings remain **per-intent**, not cumulative spend across the life of a grant. Cumulative multi-turn accounting is non-normative future work (issue #13).

## Reference

`packages/aap/src/validate.ts`, `packages/aap/src/runtime-validate.ts`, `packages/aap/src/path.ts`, `packages/aap/src/validate.test.ts`, `packages/aap/src/security-adversarial.test.ts`.
