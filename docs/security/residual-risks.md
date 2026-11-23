# Residual risks

These are limits of the reference implementation and of a deployment. They are not open authority bypasses that the regression suite still reproduces.

| Risk | What is true |
| --- | --- |
| Receipt is not an external observation | `executed: true` means the callback returned. |
| Throw after dispatch | The path records `decision: ALLOW`, `failureMode: SYSTEM_ERROR`, `execution.outcome: unknown`, and `executed: false`, and consumes the nonce. That does not prove the external write did not happen. The external system must be idempotent or reconcilable. |
| Gateway `unknown` | The downstream call did not yield a completed result. The receipt is `outcome: unknown`, `executed: false`. The nonce is consumed. See [outcome unknown](../operations/outcome-unknown.md). |
| Unhashable executor result | The path reports `executed: true`, `executionHash: unhashable`, and no receipt body. The nonce is consumed. |
| Shared store | `NonceLedger` is one process. `adap-store-postgres` coordinates only workers that share that database. It is not exactly-once across the external system. |
| Credential isolation | If the agent holds the rail credential, it can skip this path. |
| Connection exhaustion | The 2026-11-02 local drill did not fail closed for a gateway that already held a pooled connection. |
| Vault dev mode | The local drill uses Vault dev mode. See [local staging](../operations/local-staging.md). |
| Clock and policy registry | The operator supplies the clock and the policy documents. Caller `now` is rejected. |
| External retest | Not done. |
| Cumulative spend | Enforced only when a grant sets `cumulative_max_amount` or `cumulative_<field>`. `max_amount` stays per intent. The reference ledger is one process. Workers that do not share a store do not share a pool. |
| Explicit `defaultAction: ALLOW` | Unmatched calls follow that configured action. v0.1 does not rewrite it to `BLOCK`. Consequential policies should set `BLOCK`. |
| Freeform argument names | The evaluator does not run prompt text. A policy can still name a field the caller controls. There is no universal argument whitelist. |
| Receipt chain | `verifyReceiptChain` does not detect a dropped tail. |

Deployment controls that remain outside the protocol: network policy, a production secret manager, and a highly available nonce store.
