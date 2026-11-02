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
6. Sets `execution.executed` from what the runtime reported. `executed: true` means the executor callback returned. It is not an independent proof that an external system committed the action. `execution.outcome` separates that report: `not_dispatched` (this call did not make the external call), `returned` (the callback returned), or `unknown` (the external call may already have been made and the callback did not return). `executed: false` together with `outcome: unknown` does not mean that no side effect occurred. A later `not_dispatched` receipt for the same nonce describes that later call only.
7. Claims the intent nonce exclusively before calling the executor (`pending` → `consumed` | `failed`). A second claim with the same nonce while one is in flight, or after it is terminal, is `BLOCK` (`nonce_in_flight_or_used`) and does not call the executor. That second receipt is `not_dispatched` for this call. It does not prove the in-flight attempt never dispatched. Checking usability without claiming is not enough. When more than one process can execute the same intent, the claim is an atomic compare-and-swap in a store they share.
8. Does not promise exactly-once delivery across the external system. The shared store gives one dispatch attempt per nonce. If the process dies after dispatch, or the executor throws after a side effect, the nonce stays in flight or becomes `failed`, and a retry of the same intent does not dispatch again. Whether the external system applied the effect once is that system's idempotency, not a property of the nonce row. The Postgres adapter's compare-and-swap is that shared-store claim only when every worker uses the same database. Two process-local ledgers do not provide it. A store outage after dispatch leaves the outcome `unknown`.

The reference path recomputes the intent hash immediately before the executor and refuses the call if it differs from the authorized hash. It claims the nonce synchronously before `await execution()`. Its `NonceLedger` is in memory: exclusive within one process, lost on restart, and not a shared store.

## Reference

`packages/aap/src/path.ts` and `packages/aap/src/attacks.ts` (`06-post-approval-mutation`).

The reference gateway in `packages/adap-gateway` is not required by this section. When its downstream call ends as `unknown`, the executor callback returns, the path reports `executed: true`, and the nonce is consumed. `executed: true` in that case is still the callback report, not proof the external system committed. See [docs/operations/outcome-unknown.md](../docs/operations/outcome-unknown.md).
