> **Historical snapshot.** This file records an earlier audit or local drill. It is not the current state of `main`.
> Notes that name `1fa576a` or `security/adap-complete-remediation` describe that earlier tree.
> Current status: [Security status](../status.md).

# SECURITY-ATTACK-COVERAGE

Probes ran against the built working tree on `security/adap-complete-remediation` (HEAD `1fa576a`, remediation uncommitted).  
Reproduction script: `scripts/redteam-probe.mjs` unless noted.

| Attack | Expected behavior | Actual behavior | Test | Result |
| --- | --- | --- | --- | --- |
| ADAP-001 policy substitution without approval | BLOCK, no execute | `REQUIRE_HUMAN` then `BLOCK`, exec 0 | RT-05, `reproduce-findings.mjs` | Fixed |
| ADAP-001 approval reused on a different intent and nonce | BLOCK | `BLOCK` / no pending authorization, exec 0 | RT-12 | Fixed |
| ADAP-002 object nonce | Reject | Throws before ledger use | RT-07 | Fixed |
| ADAP-002 same string nonce after consume | Reject | Existing suite concurrent claim; failed-then-retry spends nonce | RT-11, `path.test.ts` | Fixed in-process |
| ADAP-003 NaN / -Infinity comparison bypass | Reject | Comparison bypass not reproduced | `reproduce-findings.mjs` | Fixed |
| ADAP-003 NaN handed to `runAuthorityPath` | BLOCK receipt | Exception escapes the function | RT-04 | Confirmed defect |
| ADAP-004 `__proto__` key | Reject | `canonicalJson` throws | `reproduce-findings.mjs` | Fixed |
| ADAP-005 inherited constraints | Reject | Plain-data-object rejection | `reproduce-findings.mjs` | Fixed |
| ADAP-006 empty agent role | BLOCK | `agent_not_in_scope` | `reproduce-findings.mjs` | Fixed |
| Omitted `agentRole` on `evaluateToolCall` | Spec-dependent | `ALLOW` on a scoped policy | RT-08 | Conditional, not an authority-path bypass |
| ADAP-008 expired `now` | BLOCK | BLOCK | RT-06 | Fixed for a trusted clock |
| ADAP-008 caller passes `now` inside the window after wall-clock expiry | Must not depend on agent time | Executes | RT-06 | Conditional |
| ADAP-010 `resource/./vault` under `resource/*` | Reject ambiguous targets | `BLOCK` / capability not granted (rest contains `/`) | RT-10, `scripts` probe | Not a bypass |
| ADAP-010 single-dot `resource/.` | Spec is ambiguous | Not rejected by `includes('..')`; one-segment wildcard can cover `resource/.` | Code inspection | Residual, not executed as a side effect |
| ADAP-011 BLOCK + allowed + executed | Reject | `structureOk=false` | RT-09 | Fixed |
| Nested field mutated during `await` after ALLOW | Executor must see the authorized value | Executor observed `evil`; decision `ALLOW` | RT-01 | Confirmed high |
| Getter that flips `amount` across reads | Reject or execute the signed value | `BLOCK` (not reproduced as a bypass) | RT-02 | Not reproduced |
| Forged negative amount, bad signature, then the real intent | Real intent still usable | Real intent `BLOCK` / nonce already used | RT-03 | Confirmed medium |
| Executor throw, then same nonce | No second execution | 1 call, second `BLOCK` | RT-11 | Fixed in-process |
| Attack 06 mutated purchase | Approval binding refusal | Refusal reason is `nonce already used` | `pnpm attacks` | Blocks execution; does not exercise the approval check |
| Process restart / second ledger | Not a distributed guarantee | Not implemented | Code inspection of `NonceLedger` | Deployment requirement |
| Direct downstream call with rail credentials | Out of scope of the library | No credential boundary in this repo | `THREAT_MODEL.md` and path review | Deployment requirement |

## Post-patch coverage appended 2026-11-01

The table above is the pre-patch audit. It is kept as the record of what the probes did before RT-01, RT-03, and RT-04 were changed. The rows below were run against the patched working tree, built `dist`, `scripts/redteam-probe.mjs`, and `packages/aap/src/rt-remediation.test.ts`.

| Attack | Expected behavior | Actual behavior | Test | Result |
| --- | --- | --- | --- | --- |
| Nested field mutated during the executor yield | Executor and receipt keep `legit` | `observed=legit`, `receiptDest=legit`, `ALLOW`, executed | RT-01 probe; `rt-remediation.test.ts` | Remediated |
| Same mutation during a policy-resolver call, after approval is recorded, and across one in-flight nonce | Authorized values only; one execution | Executor arguments equal the signed snapshot; second call `nonce_in_flight_or_used` | `rt-remediation.test.ts` | Remediated |
| Getter that flips `amount` | Execute the signed value or refuse | Probe: `observed=10`, `ALLOW`. Test: executor amount `10` | RT-02; getter test | Not a bypass |
| Forged `amount: -1` and garbage signature, then the real intent | Real intent still usable; no forged receipt | Forged `authenticated=false`, receipt absent; follow-up `REQUIRE_HUMAN` / `apply_needs_human` | RT-03 probe | Remediated |
| Invalid signature on a valid-looking payload, then replay | First does not consume; second executes once; third is replay | `ALLOW` once, then `replay`, one executor call | `rt-remediation.test.ts` | Remediated |
| Invalid signature while a valid request is in flight | Invalid request does not take the nonce | Valid request `ALLOW`; invalid request unauthenticated; replay then `replay` | `rt-remediation.test.ts` | Remediated |
| Empty, `%%%`, and `not-a-signature` | Fail closed, nonce unused | `BLOCK`, `authenticated=false`, receipt absent, ledger empty | `rt-remediation.test.ts` | Remediated |
| Signed `amount: -1` | Authenticated refusal, nonce spent, no execution | `BLOCK` / `amount`, receipt verifies, status `consumed`, replay `replay` | `rt-remediation.test.ts` | Holds |
| `NaN`, `+Infinity`, `-Infinity` into `runAuthorityPath` | Structured unauthenticated failure | No throw, `BLOCK`, receipt absent, 0 calls, reason `intent could not be canonicalized` | RT-04 probe | Remediated |
| Cycle, `Date`, function, enumerable `__proto__` | Structured failure, no execution | No throw, `authenticated=false`, 0 calls | `rt-remediation.test.ts` | Remediated |
| Signed fractional `10.5` | Authenticated receipt, no execution | `BLOCK` / `amount`, receipt verifies | `rt-remediation.test.ts` | Holds |
| ADAP-001 through ADAP-011 original shapes | Still blocked | `reproduce-findings.mjs` reports `FIXED` for 001, 002, 003, 004, 005, 006, 011. RT-05, RT-07, RT-09, RT-10, RT-11, RT-12 stay `FIXED` | Probe and script | No regression observed |
| RT-06 caller `now` | Unchanged by this patch | `CONDITIONAL` | RT-06 | Still conditional |
| RT-08 omitted `agentRole` | Unchanged by this patch | `CONDITIONAL` | RT-08 | Still conditional |
