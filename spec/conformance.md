# Conformance

A conforming implementation provides the path below. The names of packages in this repository are a reference, not a requirement.

```
Principal
  → Delegation
  → Agent
  → Signed intent
  → Policy decision
  → Human approval, when required
  → Execution boundary
  → Authorization receipt
```

## A conforming implementation MUST

| MUST | Reference test |
| --- | --- |
| Reject a child that raises `max_amount`, widens a target, outlives the parent, drops a parent constraint, or is issued by anyone but the parent subject, and not call the executor | `packages/aap/src/attacks.ts` (`01-over-delegation`), `packages/aap/src/validate.test.ts` |
| Reject re-delegation of a capability with `delegable: false`, and not call the executor | `packages/aap/src/attacks.ts` (`02-privilege-escalation`) |
| Reject an intent outside the terminal delegation, including an amount above `max_amount`, and not treat free text as a constraint | `packages/aap/src/attacks.ts` (`03-prompt-injection`), `packages/aap/src/validate.test.ts` |
| Reject an expired delegation or intent, and not call the executor | `packages/aap/src/attacks.ts` (`05-expired-delegation`) |
| Reject a consumed nonce, and not call the executor for that attempt | `packages/aap/src/attacks.ts` (`04-replay`) |
| Not call the executor on `BLOCK`, or on `REQUIRE_HUMAN` without an approval bound to the same intent hash | `packages/aap/src/attacks.ts` (`06-post-approval-mutation`), `packages/aap/src/path.ts` |
| Pass only the verified intent to the executor | `packages/aap/src/path.ts`, `spec/execution.md` |
| Bind the receipt to each presented delegation by hash, to the intent hash, to the policy pin, the rule id, and the policy content hash, and to the reported execution | `packages/aap/src/verify-published-proof.ts`, `packages/audit-verify/src/authorization-receipt.test.ts` |
| Check the Ed25519 signature only when the issuer public key is available | `packages/audit-verify/src/cli.ts`, `packages/audit-verify/src/authorization-receipt.test.ts` |
| Not treat `executed: true` as proof that an external system performed the action | `spec/execution.md`, `THREAT_MODEL.md` |

`BLOCK` and a pending human decision do not call the executor. A verifier checks the receipt offline from the issuer public key, the content hash, and, when the verifier also holds them, the delegations, the intent, and the policy document. The published files in `examples/proof/` are one such check: `node examples/verify-proof.mjs`. The six attacks are `pnpm attacks`. Structure and the content hash alone are not signature verification.

Synthetic identifiers in the examples (`resource/example`, `prn_example`, `agt_a`, `agt_b`) are not organizations.
