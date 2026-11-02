> **Historical snapshot.** This file records an earlier audit or local drill. It is not the current state of `main`.
> Notes that name `1fa576a` or `security/adap-complete-remediation` describe that earlier tree.
> Current status: [Security status](../status.md).

# SECURITY-REMEDIATION-RT01-RT04

Patch for the three confirmed findings in `SECURITY-INDEPENDENT-AUDIT.md`. The audit text is unchanged. This file records the patch that followed it.

**Branch:** `security/adap-complete-remediation`  
**HEAD:** `1fa576a8ef4a889685d5623d67c9ae71366c8f2d` (unchanged; the patch is uncommitted)  
**Date:** 2026-11-01  
**Backup before the edit:** `C:\Users\User\Desktop\adap-working-tree-backup-20261101-2119` (`tracked.patch` plus a source copy). The copy of `packages/*/src` was flattened into one `src` directory. `tracked.patch` is the pre-patch `git diff`.

No commit, push, merge, or release was made.

## RT-01 — Nested parameter mutation

### Original exploit

Sign an intent whose `parameters.meta` is `{ dest: 'legit' }`. `runAuthorityPath` returns `ALLOW`. During `await` inside the executor, set `meta.dest = 'evil'`. The executor then reads `evil`. The probe observed `ALLOW` and `dest=evil`.

### Root cause

Authorization hashed and checked a normalized copy. `executeBound` then built the executor context with `{ ...input.intent.parameters }` from the live caller object, after that await point. The copy was shallow, so nested objects stayed shared with the caller. The receipt also read `input.intent` after the await.

### Vulnerable code path

`runAuthorityPath` → `verifyAuthority` → later `executeBound`, which spread `input.intent.parameters`, and `seal`, which read `input.intent` again.

### Code change

- `packages/aap/src/snapshot.ts` deep-copies JSON-like data. Nested objects and arrays are new values. Cycles, non-plain prototypes, functions, symbols, bigints, and `__proto__` / `constructor` / `prototype` keys are rejected. `deepFreeze` freezes the validated snapshot after semantic checks.
- `presentAuthority` in `packages/aap/src/validate.ts` clones the chain and the intent before signature verification. `authorizePresented` validates amounts and delegation rules on that clone, rejects a normalized form whose hash differs from the signed payload, and freezes the result.
- `packages/aap/src/path.ts` keeps a `view` whose `intent` and `chain` are that snapshot. Policy `toolArgs`, the executor `parameters`, and the receipt `toolArgs` are separate `deepDataClone` values. `executeBound` is only called with `view`. After the snapshot exists, the path does not read the caller's `input.intent` for execution or the receipt.

### Regression test

`packages/aap/src/rt-remediation.test.ts`, describe `RT-01 immutable authorization snapshot`.

Covers a nested object, a nested array, replacement of the nested object, replacement of the top-level parameters, a flipping getter, mutation after `REQUIRE_HUMAN` and before the next call, mutation inside `markApproved` before execute, mutation inside `resolveByUri`, and one in-flight nonce plus a second caller. Assertions check the decision, the executor call count, the exact executor arguments, and `receipt.intent.argsRedacted` / `receipt.execution.intentHash`.

### Verification output

`node scripts/redteam-probe.mjs`:

```text
[REMEDIATED] RT-01 (high) observed=legit receiptDest=legit decision=ALLOW executed=true authenticated=true
```

Vitest: the six RT-01 tests passed as part of 14/14 in `rt-remediation.test.ts`.

### Remaining limitations

A caller who mutates the object before the next request changes the bytes that will be verified. Signature verification then fails and nothing executes. That is a different request, not a post-authorization edit. A process that never calls `runAuthorityPath` is outside this patch. The snapshot rejects objects that are not JSON-like; those requests fail closed.

## RT-03 — Nonce consumption before authentication

### Original exploit

Copy a valid signed intent, set `parameters.amount` to `-1`, replace `signature` with `not-a-signature`, and submit it. The ledger then rejects the original signed intent with `nonce already used`.

### Root cause

`validateSignedIntent` ran before `verifySignatures`. `assertCanonicalAmount` threw `AuthorityError` with `authenticated: true`. The `catch` in `runAuthorityPath` consumed `input.intent.nonce` whenever `error.authenticated` was set.

### Vulnerable code path

`verifyAuthority` → `validateSignedIntent` / `validateSignedDelegation` → throw → `runAuthorityPath` catch → `ledger.consume`.

### Code change

`presentAuthority` clones, checks shape, checks canonical form, and verifies signatures. `runAuthorityPath` sets `signatureVerified` only after that returns. `assertUsable` and every `consume` / `reserve` / `claimForExecution` run after that flag, and they use the snapshot nonce. The `catch` returns `unauthenticatedRejection` when the flag is unset: `BLOCK`, `authenticated: false`, no receipt, no ledger write. Semantic failures after a valid signature still consume the nonce, except `replay` and `approval`, which already mean the nonce is spoken for or must stay pending.

### Regression test

`packages/aap/src/rt-remediation.test.ts`, describe `RT-03 authentication before nonce consumption`.

Covers a bad signature with amount `-1`, a bad signature on an otherwise valid payload, the same nonce succeeding afterwards, replay of that success, an invalid signature overlapping an in-flight valid request, another caller's garbage signature on the victim nonce, empty / `%%%` / `not-a-signature`, and a validly signed amount `-1` which does consume the nonce and returns a verifiable `BLOCK` receipt.

### Verification output

```text
[REMEDIATED] RT-03 (medium) forged authenticated=false receipt=absent BLOCK/signature_invalid (intent signature invalid); legit follow-up=REQUIRE_HUMAN/apply_needs_human (Rule apply_needs_human matched: tool.name == 'apply')
```

The original probe's follow-up is `REQUIRE_HUMAN` because the reference policy asks for a person on `apply`. It is not `nonce already used`. The vitest case that uses the allow-apply policy executes once and then rejects the replay.

### Remaining limitations

The ledger is one process-local `Map`. Two OS processes do not share it. A valid signature from any principal can still spend a nonce string; the nonce is not reserved for a principal before a valid signature. An authenticated semantic failure, such as a signed negative amount, still consumes the nonce. That is intentional: the signature was valid.

## RT-04 — Canonicalization exception escapes the boundary

### Original exploit

Replace `parameters.amount` with `NaN` on a signed intent and call `runAuthorityPath`. `canonicalJson` threw while hashing, before the `try`. The caller received a rejected promise. The executor was not called. There was no `BLOCK` result.

### Root cause

`const intentHash = sha256(unsignedIntent(input.intent))` stood before the `try`. `canonicalJson` throws on non-finite numbers. `verifyObject` also catches that throw and turns it into `false`, which would otherwise look like a bad signature if hashing were only done there.

### Vulnerable code path

`runAuthorityPath` entry, before `try`, via `sha256` → `canonicalJson`.

### Code change

The public function body is inside `try`. Hashing happens only after `presentAuthority` returns. `assertCanonicalForm` runs on the unsigned snapshot before `verifyObject`, and turns a canonicalization throw into `AuthorityError('canonicalization', ..., false)`. The path catch maps that to `unauthenticatedRejection`: no throw, no receipt, no nonce consume. `sealOrClosed` covers a later seal failure so a second throw does not leave the function. An authenticated malformed value, such as signed `10.5` or signed `-1`, still gets a `BLOCK` receipt because the signature verified.

### Regression test

`packages/aap/src/rt-remediation.test.ts`, describe `RT-04 controlled authority error boundary`.

Covers `NaN`, both infinities, a cycle, a `Date`, a function, an enumerable `__proto__` key, a normal `REQUIRE_HUMAN` then approved `ALLOW`, and signed `10.5`. Each invalid case expects no thrown exception and zero executor calls. Unauthenticated cases expect `receipt` absent. The fractional case expects a verified receipt and `executed: false`.

### Verification output

```text
[REMEDIATED] RT-04 (medium) NaN threw=false decision=BLOCK authenticated=false receipt=absent executed=false calls=0 reason=intent could not be canonicalized
[REMEDIATED] RT-04 (medium) +Infinity threw=false ... reason=intent could not be canonicalized
[REMEDIATED] RT-04 (medium) -Infinity threw=false ... reason=intent could not be canonicalized
[REMEDIATED] RT-04 (medium) cycle threw=false ... reason=intent.parameters.self contains a cycle
```

### Remaining limitations

`verifyObject` and `verifyHex` still catch canonicalization errors and return `false` when called directly. The authority path does not rely on that. Unauthenticated failures do not get a receipt, so there is no artifact to verify offline. The reason strings name the field path. They do not include signature bytes. A cyclic caller-supplied policy object can still fail after a valid signature and consume that nonce, because the signature was already verified. That is a caller-policy failure, not the `NaN` intent probe.

## ADAP-001 through ADAP-011 after this patch

`node scripts/reproduce-findings.mjs` on the rebuilt `dist`:

| ID | Status |
| --- | --- |
| ADAP-001 | FIXED |
| ADAP-002 | FIXED |
| ADAP-003 | FIXED |
| ADAP-004 | FIXED |
| ADAP-005 | FIXED |
| ADAP-006 | FIXED |
| ADAP-011 | FIXED |

The script does not print ADAP-007, ADAP-008, ADAP-009, or ADAP-010. Those remain as in the audit: no new exploit was run for them beyond RT-06 (caller `now`, still conditional), RT-08 (omitted role, still conditional), and RT-10 (`resource/./vault` still `BLOCK`).

`pnpm attacks`: six `BLOCK` results. Attack 06 still says `nonce already used`.  
`pnpm demo`: `REQUIRE_HUMAN`, then `ALLOW`, receipt verified.

## Final verification counts

Recorded in full in `SECURITY-VERIFICATION-LOG.md` under "Post-patch run".

| Command | Result |
| --- | --- |
| `pnpm test` | 110 passed, 0 failed (policy 47, receipt 19, adap 44) |
| `pnpm test:security` | 16 passed (13 + 3), subset of the 110 |
| `pnpm typecheck` | exit 0 |
| `pnpm build` | exit 0 |
| `pnpm attacks` | exit 0, six BLOCK |
| `pnpm demo` | exit 0, REQUIRE_HUMAN then ALLOW |
| `node scripts/reproduce-findings.mjs` | exit 0, seven FIXED |
| `node scripts/redteam-probe.mjs` | exit 0, RT-01 / RT-03 / RT-04 REMEDIATED |

An earlier `pnpm typecheck` in the same session failed on `snapshot.ts` and was fixed before this table. It is not hidden. The counts above are from the run after that fix, including a second `pnpm test` / `pnpm test:security`.

## Decision

**READY FOR INDEPENDENT EXTERNAL RETEST.**

Not production secure. Not fully secure. RT-06, the process-local nonce store, and the other residuals in `SECURITY-REMAINING-RISKS.md` are still there.
