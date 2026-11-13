# Amounts, currency, and targets

Normative domain rules for authority limits and resource identifiers in ADAP v0.1 (security remediation).

## Amounts

| Rule | Normative meaning |
| --- | --- |
| Representation | Non-negative **safe integer** minor units (for example cents). IEEE-754 binary64 values that are safe integers. |
| Sign | `>= 0`. Negative amounts are rejected. |
| Precision | Integers only. Fractional JSON numbers are rejected. No silent coercion. |
| Range | `0` .. `Number.MAX_SAFE_INTEGER`. Outside that range → reject. |
| Overflow | Reject. Do not wrap. |
| Non-finite | `NaN`, `+Infinity`, `-Infinity` are rejected before authorization. |
| Zero | Allowed for both amounts and `max_*` caps. |
| Comparison | Deterministic numeric compare on canonical values only. |
| Scope | Every `max_<field>` key is a **per-intent** ceiling on `parameters.<field>`, not cumulative spend. `max_amount` bounds `amount`. `max_quantity` bounds `quantity`. A key that starts with `max_` but is not `max_<field>` is rejected. |

### Cumulative budgets (non-normative future)

Issue #13: silent multi-turn / cumulative spend accounting across intents is **out of scope for v0.1**. Receipt chains prove integrity of supplied receipts only. Operators that need cumulative limits must implement them outside this schema and state the semantics separately. Unknown downstream outcomes after an authorized attempt keep the nonce consumed; reconcile with idempotency at the resource.

Policy evaluation and terminal constraint enforcement must use the same normalized representation.

## Currency

| Rule | Normative meaning |
| --- | --- |
| Representation | Exactly three uppercase ASCII letters (`^[A-Z]{3}$`), ISO 4217 form. |
| Aliases | Not expanded by the reference implementation. `eur` and `Euro` are rejected. |
| Missing | When a grant constrains `currency`, the intent must present the same own-property value. |

## Targets

| Rule | Normative meaning |
| --- | --- |
| Representation | Opaque path-like string of `/`-separated segments. Compared as exact strings except for a single trailing `/*` grant prefix. |
| Segments | Each segment matches `^[A-Za-z0-9][A-Za-z0-9._~-]*$`. Empty segments, leading `/`, trailing `/`, and `//` are rejected. |
| Percent-encoding | Rejected (`%` not allowed). Do not decode into a broader permission. |
| Dot segments | `.` and `..` as whole segments are rejected. A substring `..` anywhere is also rejected. |
| Unicode | Must already be NFC and NFKC. Fullwidth separators and dots are rejected by the segment alphabet. |
| Backslashes / NUL | Rejected. |
| URL shape | Targets containing `://` are rejected. |
| Case | Opaque and case-sensitive. `resource/Example` does not cover `resource/example`. |
| Wildcard | Only as the final segment of a grant (`resource/*`). It covers one request segment (`resource/example`), not deeper paths. Request targets must not contain `*`. |

Ambiguous representations fail closed. The reference path does not rewrite a target into a different string. Authorization, policy matching, and execution all use the same canonical request string.

## Reference

`packages/aap/src/amount.ts`, `packages/aap/src/runtime-validate.ts`, `packages/aap/src/validate.ts`.
