# Reference architecture

**Status:** description of this repository. Not a production certificate.

## Protocol and implementation

The protocol is the text in [spec/](../../spec/). A conforming runtime can be written without these packages. Nothing here requires a Hardalion service.

| Piece | Package | Role |
| --- | --- | --- |
| Policy evaluation | `adap-policy` (`packages/policy-engine`) | Deterministic policy decision. Not the authority path. |
| Receipt verification | `adap-receipt` (`packages/audit-verify`) | Offline structure, content hash, and optional Ed25519 check. |
| Authority path | `adap` (`packages/aap`) | Signed intent, delegation, policy pin, nonce claim, receipt. The caller supplies `execute`. |
| Shared store | `adap-store-postgres` (`packages/adap-store-postgres`) | PostgreSQL compare-and-swap for nonces, pending approvals, policy pins, and an execution log. |
| Execution gateway | `adap-gateway` (`packages/adap-gateway`) | Process that runs the authority path and a credential broker. Reference deployment, not a required protocol dependency. |

`adap` does not embed the Postgres store. Cross-process exclusion exists only when every worker uses one shared `AsyncAtomicNonceBackend`. Two process-local ledgers do not coordinate.

## Authorization and execution

An authorization decision (`ALLOW`, `REQUIRE_HUMAN`, `BLOCK`) is not proof that an external system committed a side effect.

On the reference path:

- `BLOCK` and an unresolved `REQUIRE_HUMAN` do not call the executor.
- `executed: true` means the executor callback returned. It is not an independent observation of the external system.
- If the callback throws, the reference path records `executed: false` and marks the nonce `failed`. That receipt does not prove the callback did nothing before it threw. See [THREAT_MODEL.md](../../THREAT_MODEL.md).
- The reference gateway's `executionState: unknown` is a gateway field. The authority result stays `ALLOW` with `executed: false`, and the nonce is consumed. Reconciliation is a later read. See [outcome unknown](../operations/outcome-unknown.md).

The Postgres adapter gives one claim per nonce in that database. It does not promise exactly-once delivery across the external system. The external system needs its own idempotency.

## What this repository does not include

Identity provisioning, a production secret manager, customer networks, and hosted enforcement are outside this repository. `adap-gateway` will not stop an agent that already holds the rail credential or a network path around the gateway. That isolation is an operator property.
