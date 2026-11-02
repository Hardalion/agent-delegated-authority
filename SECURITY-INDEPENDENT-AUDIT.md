# SECURITY-INDEPENDENT-AUDIT

**Role:** Independent red-team review of the remediation working tree.  
**Repository:** `npl-spec` (Hardalion/agent-delegated-authority)  
**Branch:** `security/adap-complete-remediation`  
**HEAD commit:** `1fa576a8ef4a889685d5623d67c9ae71366c8f2d`  
**What was audited:** The uncommitted working tree on that branch. HEAD itself is still the pre-remediation revision. `git diff 1fa576a` is the remediation.  
**Date:** 2026-11-01  
**Environment:** Node v22.19.0, pnpm 10.15.1, Windows.

This review did not treat the previous pass/fail claims as evidence. Production code was not modified.

## Methodology

1. Confirmed branch, HEAD, and `git diff --stat` / `git diff --check` against `1fa576a`.
2. Read the authority path, validation, nonce ledger, receipt verifier, and policy scope check as they exist now.
3. Rebuilt `dist` and ran hostile probes in `scripts/redteam-probe.mjs` and `scripts/reproduce-findings.mjs`. The probes call the built library. They are not part of `pnpm test`.
4. Ran `pnpm test`, `pnpm test:security`, `pnpm typecheck`, `pnpm build`, `pnpm attacks`, and `pnpm demo`.

`git diff --check` reports trailing whitespace on `THREAT_MODEL.md` line 3. That is not a security defect.

## Files inspected

Security-sensitive implementation:

- `packages/aap/src/path.ts`
- `packages/aap/src/validate.ts`
- `packages/aap/src/runtime-validate.ts`
- `packages/aap/src/nonce.ts`
- `packages/aap/src/pending.ts`
- `packages/aap/src/policy-resolver.ts`
- `packages/aap/src/crypto.ts`
- `packages/aap/src/amount.ts`
- `packages/aap/src/clock.ts`
- `packages/aap/src/protocol.ts`
- `packages/aap/src/safe-object.ts`
- `packages/audit-verify/src/authorization-receipt.ts`
- `packages/policy-engine/src/engine.ts`
- `packages/policy-engine/src/evaluator.ts`
- `packages/policy-engine/src/canonical-json.ts`
- `packages/aap/src/security-adversarial.test.ts`
- `packages/aap/src/attacks.ts`
- `packages/aap/src/attacks.test.ts`
- `spec/human-approval.md`, `spec/intent.md`, `spec/amounts-and-targets.md`, `spec/delegation.md`, `spec/authorization-receipt.md`
- `THREAT_MODEL.md`
- `.github/workflows/ci.yml`

## Original findings

| ID | Independent result |
| --- | --- |
| ADAP-001 | Fixed. A pending `REQUIRE_HUMAN` resumed with `allow-apply` and no approval stays `BLOCK`. Executor call count stayed 0. Probe RT-05. |
| ADAP-002 | Fixed. An object nonce is rejected before the ledger. Probe RT-07. |
| ADAP-003 | The comparison bypass is fixed. `NaN` and `-Infinity` do not pass the amount check. A separate defect remains: `NaN` throws out of `runAuthorityPath` (RT-04). |
| ADAP-004 | Fixed. `canonicalJson` rejects an own `__proto__` key. |
| ADAP-005 | Fixed. A prototype-bearing constraint object is rejected. |
| ADAP-006 | Fixed for an empty `agentRole` (`agent_not_in_scope`). Omitting `agentRole` entirely still matches a scoped policy (RT-08). That matches the current spec sentence, which applies the check only when a role is provided. |
| ADAP-007 | No malformed intent in the probe reached `execute`. Schema rejection happens inside `verifyAuthority`. Not re-proven by a new exploit beyond the existing adversarial file. |
| ADAP-008 | Expiry is checked against the caller-supplied `now` or `clock`, not against fields inside the intent. A caller who passes a `now` inside the signed window can authorize an intent that is expired in wall-clock time (RT-06). The API documents this as a trusted input. There is no production guard that refuses a caller clock. |
| ADAP-009 | Negative, fractional, and non-finite amounts are rejected. Zero is allowed, as the spec says. |
| ADAP-010 | `resource/./vault` under `resource/*` is `BLOCK` (`capability not granted`) because the remainder `./vault` contains a slash. A single-dot segment such as `resource/.` is not rejected by `assertCanonicalTarget`, which only looks for `..`. |
| ADAP-011 | Fixed. `BLOCK` + `outcome: allowed` + `executed: true` fails structure checks. Probe RT-09. |

The original eleven findings are not still exploitable in the form reported. Three new defects are.

## New findings

### RT-01 — Nested parameter mutation after ALLOW

**Severity:** High.  
**Class:** Confirmed vulnerability in the in-process reference API.  
**Exploitability:** An agent that shares the parameter object with `runAuthorityPath` can change a nested field after authorization and before the executor reads it.

`executeBound` authorizes `verified.intent` (a normalized copy) and then builds the execution context from the live object:

```424:431:packages/aap/src/path.ts
  const ctx: ExecutionContext = {
    action: input.intent.action,
    target: input.intent.target,
    actor: input.intent.actor,
    principalId: bound.principalId,
    parameters: { ...input.intent.parameters },
    intentHash: bound.intentHash,
  }
```

The spread is shallow. Primitives (`amount`, `target`) are copied by value before `await`. Nested objects are shared. The hash re-check also runs before `await`. A mutation scheduled during `await input.execute` is invisible to the policy decision and visible to the executor.

Reproduction: `scripts/redteam-probe.mjs`, case RT-01. Observed result: decision `ALLOW`, executor read `dest=evil` after the signed value was `legit`.

This does not raise `max_amount` or change a string `target`, because those are copied before the await. It does change any nested object the executor uses as part of the side effect (beneficiary, account, route object, and similar).

A gateway that `JSON.parse`s the request into its own object graph, and never shares that graph with the agent, is not reachable by this probe. The reference function accepts live objects and does not freeze or deep-copy the verified snapshot before execution.

### RT-03 — Unsigned malformed intent consumes the nonce

**Severity:** Medium.  
**Class:** Confirmed vulnerability (availability and spec break). Not an authority expansion.

`validateSignedIntent` runs before signature verification. Amount and nonce errors are constructed with `authenticated: true`. The path then consumes the nonce:

```306:310:packages/aap/src/path.ts
    if (error instanceof AuthorityError) {
      if (error.authenticated && error.code !== 'replay' && error.code !== 'approval') {
        input.ledger.consume(input.intent.nonce, intentHash)
      }
```

Probe: copy a valid signed intent, set `amount` to `-1`, replace the signature with garbage, submit it first. Result: `BLOCK` / `amount`. The original signed intent on the same ledger then returns `BLOCK` / `nonce already used`.

The spec says an unauthenticated failure does not consume the nonce. This path does. An observer who knows the nonce can front-run the real request and retire it. They cannot cause execution.

### RT-04 — Non-finite values escape the fail-closed catch

**Severity:** Medium.  
**Class:** Confirmed defect. No execution. Wrong failure shape.

`intentHash` is computed before the `try` in `runAuthorityPath`. `canonicalJson` throws on `NaN`. The exception leaves `runAuthorityPath` instead of becoming a `BLOCK` receipt. Probe RT-04: `threw out of runAuthorityPath=true`. Downstream execution was not reached. A caller that does not catch the rejection can fail the request handler.

### RT-06 — Caller clock

**Severity:** Medium, conditional.  
**Class:** Deployment footgun already named in the API comments. Not an intent-field bypass.

Passing `now` inside the signed lifetime executes. Passing `now` after `expires_at` blocks. Nothing in the function checks that `now` came from the host clock. A gateway that forwards an agent timestamp into `now` disables expiry.

### RT-08 — Omitted agent role

**Severity:** Low, conditional.  
**Class:** Spec footgun on `evaluateToolCall` when `agentRole` is omitted. The authority path passes `verified.intent.actor`, so this probe does not bypass `runAuthorityPath`.

### RT-02 — Getter flip

Not reproduced. A getter that changed `amount` across reads failed closed (`BLOCK`) because signature verification and the hash re-check re-read the accessor. The successful bypass is the shared nested object in RT-01, not a flipping getter on a primitive.

### Attack-suite gap

`attacks.test.ts` expects attack 06 to fail with `nonce already used`. The mutated intent reuses the pending nonce, so the test never reaches the approval-to-intent binding check. The binding still held in RT-12 (approval for intent A presented with a fresh nonce for intent B: `BLOCK`, executor not called). The golden file does not prove that check.

## Test quality

The 96 passing tests use plain objects and do not retain a nested reference across `await`. They pass while RT-01, RT-03, and RT-04 exist. A green `pnpm test` does not cover those paths.

`pnpm test:security` re-runs 16 of those tests. It is not an independent suite.

## Limitations of this audit

- No multi-process nonce store exists to attack. Distributed replay was not executed. It remains unprovided.
- No fuzz corpus beyond the hand-written probes.
- Receipt hash-chain truncation was not re-executed. The implementation comment still says a dropped tail is undetectable.
- Dependency `pnpm audit` was not treated as a pass. CI runs it with `|| true`.

## Final assessment

**NOT SAFE TO MERGE.**

ADAP-001 through ADAP-011, in the forms originally reported, were not reproduced as authority bypasses. The reference path still does not bind execution to the verified snapshot. RT-01 is a confirmed high-severity mismatch between the authorized object and the object the executor reads. RT-03 and RT-04 are confirmed medium defects.

Do not describe this tree as ready for production or as fully verified. It is suitable to send for external retest only together with this report, not as a claim that the remediation is clean.

## Remediation status appended 2026-11-01

The sections above are the independent audit and are unchanged. After that audit, RT-01, RT-03, and RT-04 were patched in the same uncommitted working tree. HEAD is still `1fa576a8ef4a889685d5623d67c9ae71366c8f2d`. Nothing was committed, pushed, merged, or released.

The patch details, regression tests, and command output are in `SECURITY-REMEDIATION-RT01-RT04.md`. Short status:

| Finding | Audit result above | After the patch |
| --- | --- | --- |
| RT-01 | Confirmed. Executor observed `dest=evil`. | The executor and the receipt both keep `dest=legit`. Decision stays `ALLOW`. Probe status `REMEDIATED`. |
| RT-03 | Confirmed. The legitimate follow-up was `nonce already used`. | The forged request does not consume the nonce and has no receipt. The legitimate follow-up is `REQUIRE_HUMAN`. Probe status `REMEDIATED`. |
| RT-04 | Confirmed. `NaN` threw out of `runAuthorityPath`. | `NaN`, both infinities, and a cycle return `BLOCK` without a throw, without execution, and without a receipt. Probe status `REMEDIATED`. |

ADAP-001 through ADAP-011 were re-run after the patch. `scripts/reproduce-findings.mjs` still reports those seven scripted cases `FIXED`. `pnpm attacks` still prints six `BLOCK` results. `pnpm demo` still goes `REQUIRE_HUMAN`, then `ALLOW` with a verified receipt.

RT-06 and RT-08 were not part of this patch. They remain conditional. The in-memory nonce store is still process-local.

Post-patch decision: **READY FOR INDEPENDENT EXTERNAL RETEST**. This is not a statement that the tree is production secure or fully secure. A reviewer who did not write the patch should re-run the probes before merge.
