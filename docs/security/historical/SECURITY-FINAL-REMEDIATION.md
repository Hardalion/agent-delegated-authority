> **Historical snapshot.** This file records an earlier audit or local drill. It is not the current state of `main`.
> Notes that name `1fa576a` or `security/adap-complete-remediation` describe that earlier tree.
> Current status: [Security status](../status.md).

# SECURITY-FINAL-REMEDIATION

Final hardening pass on residual risks after RT-01 / RT-03 / RT-04.

**Branch:** `security/adap-complete-remediation`  
**HEAD:** `1fa576a8ef4a889685d5623d67c9ae71366c8f2d` (unchanged; all work uncommitted)  
**Date:** 2026-11-01  
**Backup before this pass:** `C:\Users\User\Desktop\adap-final-hardening-backup-20261101-2206`

No commit, push, merge, publish, tag, or release.

## Starting state

The working tree already contained:

- ADAP-001 through ADAP-011 remediations.
- RT-01 / RT-03 / RT-04 patches and `rt-remediation.test.ts`.
- Draft residual work: fail-closed policy identity/defaults, trusted clock rejection of `now`, tighter `assertCanonicalTarget`, `AtomicNonceBackend` on `NonceLedger`, CI audit without `|| true`, and `final-hardening.test.ts` / `fail-closed.test.ts`.

Independent inspection confirmed those drafts were real code changes, not documentation-only. This pass closed the remaining gaps those drafts left open.

## Findings closed in this pass

### RT-06 — Caller-controlled time

**Already present:** `resolveTrustedNow` rejects a caller `now` field; path uses `clock` or `systemClock`.  
**This pass:** Kept that boundary. Specs and threat model state zero skew tolerance. Tests cover expired, future, boundary, invalid clock, and rejected `now`.

### RT-08 — Missing `agentRole`

**Already present:** `isWellFormedAgentRole`; omitted/empty/malformed roles `BLOCK`.  
**This pass:** Specs updated so omitted identity is not in scope even under `["*"]`. Fail-closed suite and probe RT-08 assert the property.

### RT-10 — Resource normalization

**Already present:** Segment alphabet, reject `.` / `..`, empty segments, percent-encoding, URL shape.  
**This pass:** Spec `amounts-and-targets.md` matches the implementation. Adversarial cases cover Unicode separators, traversal, and case-sensitive matching. No silent rewrite.

### Policy registration and defaults

**Already present:** Second document for the same URI throws; `defaultAction` required in schema; evaluate path returns `default_action_required`.  
**This pass:** `policyResolver` is **required** on `runAuthorityPath`. Unknown URIs are not registered from the caller. Caller `policy` must hash to the pin on first evaluation and on continuation. Specs no longer say absent default means ALLOW.

### Nonce and pending stores

**Already present:** Sync compare-and-swap backend.  
**This pass:**

- Documented `AsyncAtomicNonceBackend` contract.
- Added `SharedNonceLedger` for async shared stores.
- Path awaits all nonce/pending store operations.
- Deterministic shared-store race test with an async double.
- Explicit test that two process-local backends do **not** coordinate.
- No claim of distributed safety without a real shared atomic store.

### Approval binding and attack 06

**Problem:** Mutated intent with a stolen approval failed as `nonce already used` or `no pending`, masking the binding check.  
**Fix:** After hashing the presented intent, if an approval's `intent_hash` differs, throw `approval is not bound to this intent` before the nonce gate. Attack 06 restored to that reason. Dedup keys are recorded only after signature and lifetime checks.

### Executor / receipt honesty

**Problem:** A callback that returned and then failed in seal/bookkeeping could look like "nothing executed".  
**Fix:** Split the executor try/catch from post-return consume/seal. If the callback returns, the path reports `executed: true`. If the result cannot be hashed, it returns `executionHash: unhashable` without fabricating a receipt, and the nonce stays consumed.

### CI dependency audit

**Already present:** `pnpm audit --prod --audit-level high` without `|| true`.  
**This pass:** Audit all dependencies at `--audit-level high`. Local `pnpm audit` reported no known vulnerabilities. No suppressions registered.

## Intermediate failures (not hidden)

1. `final-hardening` approval receipt check passed a string where a `KeyObject` was required → fixed with `importPublicKey`.
2. Attack 06 still printed `nonce already used` against a stale `dist` and because binding ran after the nonce gate → rebuilt; early binding check added; golden regenerated.
3. Missing-`defaultAction` authority-path test threw `ZodError` at resolver register → split into evaluateToolCall assertion plus unknown-URI path.
4. Reordering `authorizePresented` before `assertUsable` broke RT-03 "consume then replay" → restored assertUsable before semantic authorization, keeping the early approval-hash check.

## Files touched (this pass, principal)

- `packages/aap/src/path.ts`, `nonce.ts`, `pending.ts`, `validate.ts`, `index.ts`, `attacks.ts`, `attacks.test.ts`, `rt-remediation.test.ts`, `security-adversarial.test.ts`, `final-hardening.test.ts`
- `packages/aap/src/adversarial-final.test.ts` (new)
- `packages/aap/README.md`
- `scripts/redteam-probe.mjs`
- `examples/attacks/06-post-approval-mutation.txt`
- `package.json`, `.github/workflows/ci.yml`
- `spec/policy-schema.md`, `spec/deterministic-evaluation.md`, `spec/amounts-and-targets.md`
- `THREAT_MODEL.md`
- Final security deliverables in this directory

## Decision

**READY FOR INDEPENDENT EXTERNAL RETEST**

Not production ready. Not fully secure. High/Critical authority-path findings from the residual list are closed in the reference implementation with regression tests. Distributed replay protection remains a deployment requirement.
