# Deployment checklist

For operators who run ADAP in front of real systems. The protocol and the reference path decide whether an action is authorized. Some of the guarantees in [THREAT_MODEL.md](../../THREAT_MODEL.md) also depend on how the deployment is built. This page lists those deployment properties in one place.

This is not a certification, and it adds no requirement beyond [spec/](../../spec/) and the threat model. A deployment that skips a line does not get the guarantee that line protects. The reference packages, a local Compose drill, and a passing test suite are not a production deployment.

## Credentials

The receipt labels `extensions.enforcement_mode` and `extensions.credential_boundary` are set by the operator. They record a claim. They do not check it.

| | Check | How to confirm |
| --- | --- | --- |
| C1 | The agent process holds only the key it signs intents with. It holds no rail, tool, or API credential. | Inspect the agent's environment, mounted secrets, and configuration. Run a secret scanner over its image. |
| C2 | The authority check runs out of process, in a gateway, sidecar, or MCP gateway. An in-process callback is for local testing. | The agent never imports the executor. The gateway process passes `enforcementMode: 'gateway'` and `credentialBoundary: 'gateway_isolated'` so receipts record that claim. The reference gateway does not set them for you, and the default is `in_process` / `caller_supplied`. |
| C3 | Credentials live in a secret manager reachable only by the gateway. The secret manager is not in dev mode. | The reference drill uses Vault dev mode. Production does not. See [local staging](local-staging.md). |
| C4 | The write endpoint accepts requests only from the gateway, and the network gives the agent no other route to that endpoint or its credential. | From the agent's network namespace, call the endpoint directly. The call must fail. |

## Shared state

The in-memory stores in `packages/aap` are correct for one process only.

| | Check | How to confirm |
| --- | --- | --- |
| S1 | Every gateway instance uses one shared atomic nonce store, keyed by `(actor_id, nonce)`. | Present the same signed intent to two instances at once. Exactly one executes. Reference: `PostgresAtomicNonceBackend` and `SharedNonceLedger` in `packages/adap-store-postgres`. Exclusion holds only when every instance uses the same database. |
| S2 | The pending `REQUIRE_HUMAN` store is shared, and its approval queue cap is enforced atomically. | Same two-instance test with a pending approval. Reference: `PostgresPendingStore`. |
| S3 | If any grant sets `cumulative_max_amount` or `cumulative_<field>`, every worker charges the same spend ledger. | The gateway uses `PostgresSpendLedger` and migration 005. Workers with separate ledgers do not share a budget. |
| S4 | New intents use nonces with at least 128 bits from a CSPRNG. | Use `generateSecureNonce` or an equivalent. |
| S5 | Downstream writes are idempotent or reconcilable by intent hash. | A throw after a partial write, or an unknown outcome, still consumes the nonce and does not prove the write did not happen. See [outcome unknown](outcome-unknown.md). |

## Configured checks

| | Check | How to confirm |
| --- | --- | --- |
| K1 | `audience`, `rootAuthority`, and `revocationCheck` are configured, and `unsafeDevAllowUnconfiguredChecks` is not set. Check this at every layer that calls the authority path, including wrappers. | On a sample of production receipts, `extensions.checks_applied.unsafe_dev_unconfigured_checks` is `false`, and `root_authority` and `revocation_check` are `true`. A receipt with the dev flag is not a conformance receipt. |
| K2 | Human approvers are provisioned out of band as `kind: human` in the authority directory. `approvalPolicy` rejects non-human approvers and self-approval. | `checks_applied.approval_policy` and `checks_applied.no_self_approval` are `true`. |
| K3 | Consequential policies set `defaultAction: BLOCK`. | Review every registered policy. An explicit `defaultAction: ALLOW` is followed as written. |
| K4 | `issuedAtSkewMs` is `0` unless clock drift requires more, and never above 5 minutes. | Receipts record a non-zero value in `extensions.issuedAtSkewMs`. |
| K5 | Policy-only helpers such as `McpToolGate` are not described or relied on as ADAP enforcement. | Authority-enforcing MCP follows [mcp-binding.md](../../spec/mcp-binding.md). |

## Clock, policies, and keys

| | Check | How to confirm |
| --- | --- | --- |
| T1 | Authorization time comes from the gateway host clock, kept in sync. Never from the request. | The path rejects a `now` field. Monitor the host's time synchronization. |
| T2 | Policy documents are registered by the operator before requests are served. A published `{policy-id}@{version}` is never edited in place. | The resolver rejects a different body for a registered URI. Changes ship as a new version. |
| T3 | The receipt issuer key is held by the gateway, not the agent. Verifiers get the public key out of band. | `adap-receipt <receipt.json> --public-key <spki.txt>` verifies a sample receipt. |
| T4 | Rotation and revocation are defined for agent, approver, and issuer keys. | The authority directory marks retired keys `revoked`. The ceremony itself is implementation-defined in this draft. |
| T5 | When receipts are chained, signed checkpoints of the head are published somewhere the issuer does not control. | Without a checkpoint, `verifyReceiptChain` does not detect a dropped tail. See [authorization-receipt.md](../../spec/authorization-receipt.md) §7. |

## Using receipts as evidence

| | Check | How to confirm |
| --- | --- | --- |
| E1 | Receipts are verified with the issuer public key. | `status` is `verified`. `integrity_only` means no signature was checked. |
| E2 | `executed: true` is treated as the executor's report, not proof that the external system committed. | Confirm consequential actions against the downstream system's own records. |

Remaining limits that no deployment step removes are in [residual risks](../security/residual-risks.md).
