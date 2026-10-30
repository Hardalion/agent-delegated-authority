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
7. Claims the intent nonce exclusively before calling the executor (`pending` → `consumed` | `failed`). A second claim with the same nonce while one is in flight, or after it is terminal, is `BLOCK` (`nonce_in_flight_or_used`). Checking usability without claiming is not enough. When more than one process can execute the same intent, the claim is an atomic insert in a store they share, for example a unique key or `SET NX`.
8. Executes at most once per nonce. A claim that never reaches a terminal state, because the process crashed, stays `pending` and blocks that nonce. A failed executor marks the nonce `failed`. Neither is retried with the same signed intent. A retry is a new intent with a new nonce, so it is authorized and receipted again.

The reference path recomputes the intent hash immediately before the executor and refuses the call if it differs from the authorized hash. It claims the nonce synchronously before `await execution()`. Its `NonceLedger` is in memory: exclusive within one process, lost on restart, and not a shared store.

## Reference

`packages/aap/src/path.ts` and `packages/aap/src/attacks.ts` (`06-post-approval-mutation`).
