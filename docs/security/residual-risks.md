# Residual risks

These are limits of the reference implementation and of a deployment. They are not open authority bypasses that the regression suite still reproduces.

| Risk | What is true |
| --- | --- |
| Receipt is not an external observation | `executed: true` means the callback returned. |
| Throw after a partial write | The path records `executed: false` and spends the nonce. That does not prove the external write did not happen. The external system must be idempotent or reconcilable. |
| Gateway `unknown` | The callback returned an unknown downstream state. The nonce is consumed. The receipt is `ALLOW` with `executed: false` and `extensions.executionState = unknown`. That is not a confirmed commit and not a claim the effect was prevented. See [outcome unknown](../operations/outcome-unknown.md). |
| Unhashable executor result | The path reports `executed: true`, `executionHash: unhashable`, and no receipt body. The nonce is consumed. |
| Shared store | `NonceLedger` is one process. `adap-store-postgres` coordinates only workers that share that database. It is not exactly-once across the external system. |
| Credential isolation | If the agent holds the rail credential, it can skip this path. |
| Connection exhaustion | The 2026-11-02 local drill did not fail closed for a gateway that already held a pooled connection. |
| Vault dev mode | The local drill uses Vault dev mode. See [local staging](../operations/local-staging.md). |
| Clock and policy registry | The operator supplies the clock and the policy documents. Caller `now` is rejected. |
| External retest | Not done. |
| Cumulative spend | `max_amount` is per intent. |
| Receipt chain | `verifyReceiptChain` does not detect a dropped tail. |

Deployment controls that remain outside the protocol: network policy, a production secret manager, and a highly available nonce store.
