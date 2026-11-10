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
- raise `max_amount` (canonical safe-integer minor units; see [amounts-and-targets.md](amounts-and-targets.md))
- pass on a capability marked `delegable: false`
- drop a parent constraint, including by relying on inherited / prototype properties

Constraints are normalized to own-property data-only objects before narrowing and before terminal enforcement. Prototype-bearing constraint objects are rejected. Missing own constraints are not treated as unlimited authority.

A target `resource/*` covers `resource/example`. It does not cover a deeper path.

## Root of authority (proposed)

> Status: proposed in review. Not implemented by the reference path at `bc5ae76`.

A signature from a key in the directory does not make its holder a principal. Today `verifySignatures` accepts any directory key as an issuer, and the only root check is that the root names no parent. An agent whose key is in the directory (it must be, to sign intents) can sign `{issuer: self, subject: self, constraints: {}}` and act under it.

A conforming verifier:

1. Holds an operator-owned **root-of-authority** configuration: which identities may issue a root delegation, and for which `action` and `target` namespaces.
2. Rejects a root whose issuer is not listed for every capability it grants. Rule `root_not_authorized`.
3. Rejects a root whose issuer is also its subject, unless the configuration allows it for that namespace.
4. Distinguishes identity kinds (`human`, `agent`, `service`) in the directory it verifies against. An id-to-key map is not enough.

## Revocation (proposed)

> Status: proposed in review.

A delegation is valid until `expires_at`. There is no way to withdraw it earlier except by rotating the issuer key, which withdraws every grant from that issuer.

A conforming runtime checks each `delegation_id` in the presented chain against an operator-owned revocation status at decision time, and again before continuing an approved `REQUIRE_HUMAN`. A revoked link is `BLOCK` with rule `revoked`. A revocation status that cannot be read fails closed.

## Constraint scope (proposed)

Constraints currently apply to the whole delegation, not to one capability. That is why the reference path exempts actions literally named `read` and `search` from `max_amount` (`validate.ts`). A tool with another name is not exempt, and a side-effecting tool named `search` is.

Proposed: constraints attach to a capability. Parameters not named by any constraint are unbounded today, so a recipient, payee, or URL field is open unless listed. A capability may set `closed: true`, under which any parameter not named by a constraint or an allowed-parameter list is `BLOCK`.

## Reference

`packages/aap/src/validate.ts`, `packages/aap/src/runtime-validate.ts`, `packages/aap/src/validate.test.ts`, `packages/aap/src/security-adversarial.test.ts`.
