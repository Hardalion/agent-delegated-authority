# Outcome unknown

Reference-gateway behavior in this repository. It is not a protocol requirement that every runtime use these field names.

`executionState: unknown` means the downstream call left the process and did not yield a completed or failed HTTP result. The executor throws. The authority path reports `ALLOW`, `executed: false`, and `outcome: unknown`, and the nonce is not reusable. `executed: false` does not prove the external system did nothing. Reconciliation is a later read of the downstream ledger. It does not POST.

# OUTCOME-UNKNOWN-RECONCILIATION

## Behavior

The downstream server commits the intent hash, then can drop the socket before the HTTP response (`POST /control/drop-next` on loopback inside that container).

The gateway:

1. Records `started` in `adap_execution_log` before the POST.
2. On a dropped connection, classifies the call as `unknown`.
3. Throws, so the authority path records `outcome: unknown` instead of pretending the call did not happen.
4. The nonce is not reusable, so the same signed intent is not dispatched again.
5. `GET /v1/reconcile/:intentHash` reads the downstream ledger. It does not POST. It moves `unknown` or `started` to `reconciled`.

## Measured run

| Step | Observation |
| --- | --- |
| Authorize while drop-next was armed | `executionState: unknown`, `executed: false`, `executionKnowledge: unknown` |
| Same intent to the other replica | `decision: BLOCK`, `executed` not true |
| `GET /v1/reconcile/{intentHash}` | `state: reconciled`, `detail: downstream_has_one_record` |
| Downstream business writes | 3 after this step (one replay, one approval, one unknown). No second business row for the unknown intent |

The authority result is `executed: false` with `outcome: unknown`. That does not mean the business transaction was known to be committed, and it does not mean the call never happened. Reconciliation is what established that the downstream ledger had one record.

A paused Postgres is a different case. The gateway returns HTTP 503 with `executed: false` and `executionState: not_dispatched` before the claim. After unpause, the same nonce can run once.

Automatic retry of an unknown or timed-out non-idempotent call is not implemented.
