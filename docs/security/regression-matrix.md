# Regression matrix

Current map of ADAP-001 through ADAP-011 to tests in this repository. Historical audit notes are no longer maintained in the public tree; previous versions remain in this repository's Git history and are not the current state.

| ID | Original behavior | Fix | Regression test | Status |
| --- | --- | --- | --- | --- |
| ADAP-001 | Pending REQUIRE_HUMAN resumed with permissive policy → execute without approval | PendingAuthorizationStore + approval context binding + policy pin/resolver; pending nonce cannot continue without approval | `packages/aap/src/security-adversarial.test.ts` (ADAP-001) | Fixed and verified |
| ADAP-002 | Object Map keys allowed replay after JSON.parse | Strict string nonce validation before ledger use | `security-adversarial.test.ts`: object rejection on two independent parses, and a second `runAuthorityPath` after `JSON.parse` of the same signed intent | Verified 2026-11-02 by `pnpm test:security` and `node scripts/reproduce-findings.mjs` |
| ADAP-003 | NaN / -Infinity bypassed `amount > max` | Canonical safe-integer amounts, and numeric policy comparisons fail closed | `fail-closed.test.ts` ADAP-003 (`args.amount > 100`, default ALLOW, non-finite input must be `BLOCK` / `amount_not_finite`); `security-adversarial.test.ts` intent boundary | Verified 2026-11-02 by `pnpm test:security`. The original assessment PDF is not in this repository |
| ADAP-004 | `__proto__` / inherited props could desync signature vs evaluation | Safe canonical JSON + own-property normalization + hasOwn in evaluator | `security-adversarial.test.ts` (ADAP-004) | Fixed and verified |
| ADAP-005 | Inherited constraints satisfied narrowing but vanished at terminal `Object.entries` | Normalize own-property constraints; reject non-plain objects | `security-adversarial.test.ts` (ADAP-005) | Fixed and verified |
| ADAP-006 | Empty `agentRole` bypassed `targetAgents` | Empty role out of scope; schema rejects empty entries | `security-adversarial.test.ts` (ADAP-006); `engine.test.ts` | Fixed and verified |
| ADAP-007 | Missing/malformed intent fields could reach deeper path | `runtime-validate.ts` plus rejection inside `runAuthorityPath` before `execute` | `security-adversarial.test.ts`: malformed intent at `runAuthorityPath`, executor count 0. Schema-only checks are not this test | Verified 2026-11-02 by `pnpm test:security`. Not covered by `reproduce-findings.mjs` |
| ADAP-008 | Caller `now` could move expiry | `resolveTrustedNow` rejects `now`. Expiry uses `Clock` | `security-adversarial.test.ts`: expired `FixedClock` plus caller `now` inside the signed window, executor count 0, rule `clock`. This is the ADAP-008 case. RT-06 in `final-hardening.test.ts` is the same scenario, not a substitute name | Verified 2026-11-02 by `pnpm test:security` and `node scripts/redteam-probe.mjs` (RT-06) |
| ADAP-009 | Amount domain underspecified | `spec/amounts-and-targets.md` + `amount.ts` | Adversarial amount tests + spec | Fixed and verified |
| ADAP-010 | Target/currency ambiguity underspecified | Spec + reject ambiguous targets / non-ISO currency | `security-adversarial.test.ts` (ADAP-009/010) | Fixed and verified |
| ADAP-011 | Receipt verifier accepted contradictory action/outcome/execution | Semantic invariants in `authorization-receipt.ts` | `security-semantics.test.ts`; adversarial ADAP-011 | Fixed and verified |

## Final classification

| Class | IDs |
| --- | --- |
| Fixed and verified | ADAP-001 … ADAP-011 |
| Fixed but not fully verified | — |
| Partially addressed | — |
| Not addressed | — |
| Requires deployment-level controls | Distributed nonce/pending atomicity; out-of-process credential isolation; operator-trusted policy pre-registration; production trusted clock wiring |
