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

## Constraint profiles

Constraint meaning depends on the signed-object profile. See [signed-objects.md](./signed-objects.md).

### Legacy v0.1

- `max_amount` is a per-intent ceiling on `parameters.amount`.
- Every other constraint key, including `max_quantity`, requires **exact equality** on that parameter name.
- A legacy grant with `max_quantity: 5` does **not** authorize `quantity: 3` as a ceiling. Treating it as a ceiling after a verifier upgrade would silently widen authority and is forbidden.
- When narrowing, a legacy child may only **lower** `max_amount`. Changing `max_quantity` (or any non-amount key) is rejected as altering an exact-match constraint. A child cannot introduce 0.2 ceiling semantics under a legacy parent.

### Signed-object 0.2 (`ceilings-v1`)

A constraint key `max_<field>` is a per-intent ceiling on `parameters.<field>`.

| Constraint | Bounded parameter |
| --- | --- |
| `max_amount` | `amount` |
| `max_quantity` | `quantity` |
| `max_records` | `records` |

`<field>` matches `^[A-Za-z][A-Za-z0-9_]*$`. The value is a canonical non-negative safe integer. The intent parameter must be present and must be less than or equal to the ceiling. Echoing the ceiling as its own parameter does not satisfy it: `{ quantity: 999, max_quantity: 5 }` is outside a grant of `max_quantity: 5`. A missing bounded parameter fails closed.

`read` and `search` may omit `amount` when the only ceiling in question is `max_amount`. That exception does not apply to other actions or to other `max_<field>` keys.

`max_amount` is a per-intent ceiling. It does not add up across intents.

`cumulative_max_amount` is the running sum of `parameters.amount`. Any `cumulative_<field>` key is the running sum of `parameters.<field>` in the same units. A child may only lower it. When any delegation in the presented chain sets one, the runtime must pass a spend ledger or the path fails closed and does not execute. One intent cannot exceed the pool, and later intents cannot push the sum over it. A reused delegation id with a lower ceiling has its own pool, so the higher ceiling is not spent against the lower cap. Monetary pools require `currency` on the grant and the intent. A missing or different currency is `BLOCK`, and two currencies are not added together. `read` and `search` with no `amount` charge zero for the amount pool.

`closed: true` rejects any parameter key that is not the field of a `max_<field>` ceiling, `currency`, or an exact-match constraint. `tool_definition_hash` is not a parameter. It is the MCP tool-definition pin in [mcp-binding.md](./mcp-binding.md). An authority-enforcing MCP call (`target` under `mcp/`) MUST set it. A non-MCP grant leaves it optional. A chain longer than 8 links is rejected before signature verification.

`aud` is required on every delegation, intent, and approval. A production runtime MUST set `audience` and MUST reject a missing or different `aud` (`AUDIENCE_MISMATCH`). The same default applies to root of authority, revocation, and human approver kind below. The only opt-out is `unsafeDevAllowUnconfiguredChecks: true`. That flag is dev-only. A receipt minted under it sets `extensions.checks_applied.unsafe_dev_unconfigured_checks` to true, and a verifier MUST NOT report that receipt as `verified`.

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

A production runtime MUST supply `rootAuthority`. A missing hook is `BLOCK` (`root authority is required`). A failed check is `BLOCK` (`root_not_authorized`). `unsafeDevAllowUnconfiguredChecks: true` is the only way to run without the hook, and the receipt records that opt-out in `checks_applied`.

## Lifetime

`expires_at - issued_at` must be at most 24 hours for every delegation and every intent. The reference path rejects a longer window (`authority lifetime exceeds 24 hours`). That cap is what makes a grant die without a revocation service. Early withdrawal is still the revocation hook below.

## Revocation

A delegation is valid until `expires_at` unless revoked earlier, and never past the 24 hour cap. Key rotation withdraws every grant from that issuer; per-delegation revocation is finer-grained.

A conforming runtime that supports revocation:

1. Checks each `delegation_id` in the presented chain against an operator-owned revocation status at decision time.
2. Checks again before continuing an approved `REQUIRE_HUMAN`.
3. Treats a revoked link as `BLOCK` with rule `revoked`.
4. Fails closed when revocation status cannot be read.

A production runtime MUST supply `revocationCheck`. A missing hook is `BLOCK` (`revocation check is required`). `revoked` and `unavailable` are `BLOCK`. `unsafeDevAllowUnconfiguredChecks: true` is the only way to run with expiry alone, and the receipt records that opt-out in `checks_applied`.

## Constraint scope

In v0.1, constraints apply to the whole terminal delegation. Parameters not named by any constraint are unbounded unless policy rules cover them or the grant sets `closed: true`. Per-capability constraints are not in this profile.

`max_<field>` ceilings remain per-intent. `cumulative_max_amount` and `cumulative_<field>` are the running sums, charged on the spend ledger before execution. A grant that sets one and a runtime that does not pass a ledger is `BLOCK`. The reference ledger is in-process. More than one worker MUST share a ledger store. See [amounts-and-targets.md](./amounts-and-targets.md).

## Reference

`packages/aap/src/validate.ts`, `packages/aap/src/runtime-validate.ts`, `packages/aap/src/path.ts`, `packages/aap/src/validate.test.ts`, `packages/aap/src/security-adversarial.test.ts`.
