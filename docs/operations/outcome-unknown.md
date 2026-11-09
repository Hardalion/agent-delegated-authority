# Outcome unknown

Reference-gateway behavior in this repository. It is not a protocol requirement that every runtime use these field names.

`executionState: unknown` means the downstream call did not yield a completed or failed HTTP result. The executor callback returns that state. The authority path keeps decision `ALLOW`, sets `execution.executed` to false, stores `extensions.executionState = unknown` on the receipt, and consumes the nonce. `executed: false` means the side effect was not confirmed. It is not a `BLOCK` and it is not a claim that the downstream system reversed or skipped the effect. Reconciliation is a later read of the downstream ledger. It does not POST.

# OUTCOME-UNKNOWN-RECONCILIATION

## Behavior

The downstream server commits the intent hash, then can drop the socket before the HTTP response (`POST /control/drop-next` on loopback inside that container).

The gateway:

1. Records `started` in `adap_execution_log` before the POST.
2. On a dropped connection, classifies the call as `unknown`.
3. Returns that state to the authority path instead of pretending the call did not happen.
4. The nonce is consumed, so the same signed intent cannot be executed again.
5. `GET /v1/reconcile/:intentHash` reads the downstream ledger. It does not POST. It moves `unknown` or `started` to `reconciled`.

## Earlier measurement

This table is the 2026-11-02 staging observation, from before unknown results were sealed with `executed: false`. It is not the current contract.

| Step | Observation |
| --- | --- |
| Authorize while drop-next was armed | `executionState: unknown`, `executed: true` |
| Same intent to the other replica | `decision: BLOCK`, `executed` not true |
| `GET /v1/reconcile/{intentHash}` | `state: reconciled`, `detail: downstream_has_one_record` |
| Downstream business writes | 3 after this step (one replay, one approval, one unknown). No second business row for the unknown intent |

The authority receipt's `executed: true` means the executor returned. The returned body says the downstream outcome is `unknown`. It does not mean the business transaction was known to be committed at response time. Reconciliation is what established that the downstream ledger had one record.

A paused Postgres is a different case. The caller timed out, and after unpause the nonce was `consumed`. The retry was `BLOCK`. One commit happened. The caller did not get a second execution.

Automatic retry of an unknown or timed-out non-idempotent call is not implemented.
