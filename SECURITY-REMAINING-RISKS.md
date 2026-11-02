# SECURITY-REMAINING-RISKS

Unresolved after the independent review. Ordered by severity.

## Confirmed

| ID | Severity | Issue | Why it is still open |
| --- | --- | --- | --- |
| RT-01 | High | Nested parameter objects are shared with the executor across `await`. Authorized value and executed value can differ. | `executeBound` shallow-copies `input.intent.parameters` instead of the verified snapshot. Reproduced. |
| RT-03 | Medium | A signature-invalid intent with a bad amount consumes the nonce and blocks the real signed intent. | Schema errors are flagged authenticated before signature verification, and the catch consumes the nonce. Reproduced. |
| RT-04 | Medium | `NaN` (and other values `canonicalJson` rejects) throw out of `runAuthorityPath`. No BLOCK receipt. | Hash is computed before the `try`. Reproduced. No execution in the probe. |

## Conditional

| ID | Severity | Issue | Condition |
| --- | --- | --- | --- |
| RT-06 | Medium | Expiry follows the caller `now`. | The gateway copies an agent timestamp into `now` or `clock`. |
| RT-08 | Low | `evaluateToolCall` without `agentRole` ignores `targetAgents`. | A caller uses the policy engine directly and omits the role. Not observed on `runAuthorityPath`. |
| Single-dot target | Low | `assertCanonicalTarget` rejects `..` only. `resource/.` can match `resource/*`. | A downstream parser collapses `.` segments. Not shown to change an amount or to pass `resource/./vault`. |
| Policy default | Low | Omitted `defaultAction` means `ALLOW`. | An operator loads a policy that omits the field. |
| First resolver registration | Medium | The first `register` for a URI pins that document. | Untrusted code can call `register` before the operator on a shared resolver. |

## Deployment, not implemented here

- In-memory nonce and pending stores are lost on restart and are not shared across processes. Replay protection is single-process only.
- An agent with a direct credential can skip `runAuthorityPath`. This repository does not hold or broker that credential.
- Receipt `executed: true` is the callback's report. It is not an observation of an external system.
- A receipt chain does not reveal a withheld tail.
- `max_amount` is not a running total.
- Human approval is verified only when the directory contains the approver's public key and the caller supplies the approval object. There is no revocation list.
- CI `pnpm audit` is allowed to fail (`|| true`).

## Not accepted as vulnerabilities

- RT-02 getter flip on `amount`: blocked in the probe.
- ADAP-001 through ADAP-011 in their original shapes: not reproduced as execution beyond the grant.
- `resource/./vault` under a one-segment wildcard: blocked, because the remainder contains a slash.

## Remediation appended 2026-11-01

RT-01, RT-03, and RT-04 are no longer open in this working tree. The confirmed table above is the audit record, not the post-patch state. The patch and its limits are in `SECURITY-REMEDIATION-RT01-RT04.md`.

Still open after that patch:

| ID | Severity | Issue |
| --- | --- | --- |
| RT-06 | Medium, conditional | Caller-supplied `now` is still trusted. |
| RT-08 | Low, conditional | `evaluateToolCall` without `agentRole` still ignores `targetAgents`. `runAuthorityPath` still passes the actor. |
| Nonce scope | Deployment | The ledger is in-memory and process-local. Concurrent claims are exclusive only inside that process. |
| Single-dot target | Low | `resource/.` is still not rejected by `assertCanonicalTarget`. |
| Attack 06 assertion | Test gap | `pnpm attacks` still reports `nonce already used` for the mutated purchase. RT-12 still blocks an approval presented with a different nonce. |
| First resolver registration | Medium, conditional | The first `register` for a URI still pins that document. |
| Omitted `defaultAction` | Low | Still means `ALLOW` in policy evaluation. |
| CI `pnpm audit` | Process | Still allowed to fail with `\|\| true`. |

No new authority-bypass was observed while re-running the ADAP-001 through ADAP-011 scripts, the attack catalogue, or the red-team probe. That is not a claim that no further defects exist.

## Final hardening appended 2026-11-01

The residual table above is the post-RT01/03/04 audit record. The final hardening pass closed RT-06, RT-08, resource `resource/.`, missing `defaultAction`, required policy resolver, approval-binding attack 06, CI audit gating, and the async nonce adapter contract. Current residual risks live in `SECURITY-RESIDUAL-RISKS.md`. Verification: `SECURITY-FINAL-VERIFICATION.md`.
