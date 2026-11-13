# Execution boundary

**Status:** Public Draft (v0.1).

Authorization is not the side effect. A conforming runtime keeps them apart.

```
Authorization
  ↓
Execution boundary
  ↓
External effect
```

## Invariant

The exact authorized intent is the intent that reaches the execution boundary.

A conforming runtime:

1. Does not call the executor unless the decision is `ALLOW`. `BLOCK` and an unresolved `REQUIRE_HUMAN` return before the executor.
2. Passes the verified unsigned intent to the executor. The action, the target, and the parameters are that intent. They are not a later rewrite.
3. Requires a human approval, when the policy requires one, to name the same intent hash.
4. Does not execute an intent that changed after that approval.
5. Records `execution.intentHash` on the receipt. A verifier that holds the unsigned intent checks that its reference-profile hash equals that field.
6. Sets `execution.executed` from what the runtime reported. `executed: true` is not an independent proof that an external system performed the action.
7. Claims the intent nonce exclusively before calling the executor (`pending` → `consumed` | `failed`). Nonce state is keyed by `(actor_id, nonce)` from the verified intent. A second claim with the same actor and nonce while one is in flight, or after it is terminal, is `BLOCK` (`nonce_in_flight_or_used`). Checking usability without claiming is not enough. When more than one process can execute the same intent, the claim is an atomic compare-and-swap in a store they share.
8. Executes at most once per `(actor, nonce)`. A claim that never reaches a terminal state, because the process crashed, stays `pending` and blocks that pair. A failed executor marks the nonce `failed`. Neither is retried with the same signed intent. A retry is a new intent with a new nonce, so it is authorized and receipted again. A human `DENY` retires the nonce without calling the executor.

The reference path recomputes the intent hash immediately before the executor and refuses the call if it differs from the authorized hash. It claims the nonce synchronously before `await execution()`. Its `NonceLedger` is in memory: exclusive within one process, lost on restart, and not a shared store.

## Reference

`packages/aap/src/path.ts` and `packages/aap/src/attacks.ts` (`06-post-approval-mutation`).

The reference gateway in `packages/adap-gateway` is not required by this section. When its downstream call ends as `unknown`, the executor callback returns, the path reports `executed: true`, and the nonce is consumed. `executed: true` in that case is still the callback report, not proof the external system committed. See [docs/operations/outcome-unknown.md](../docs/operations/outcome-unknown.md).

Intent `action` is an exact string. The authority check does not trim or case-fold it, because that would authorize a different action than the one that was signed. The reference gateway refuses the broker call unless `ctx.action` is already equal to its canonical form (`^[a-z][a-z0-9._-]{0,127}$` after the same trim and lowercase the helper uses). Mixed-case, padded, and otherwise non-canonical actions are `BLOCK`. `resolveHandle` and `execute` are not called, and the receipt does not claim execution. Canonical form is enforced at that boundary rather than by rewriting the signed intent.

`executionStatePersistence` on the gateway result is `not_configured`, `not_attempted`, `callback_returned`, `confirmed`, or `failed`. `not_configured` means no callback was supplied. `not_attempted` means a callback was supplied and this request never called it, including when authorization blocks before execution. `callback_returned` means every call returned and at least one did not report a durable write. `confirmed` means every call returned `'confirmed'` after its own durable write. A void return is not that confirmation. A failure before the downstream call prevents the call. A failure after the call is visible and does not repeat the call, does not change the nonce, and does not report `executed: false` when the downstream call already returned.
