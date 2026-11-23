# Outcome unknown

Reference-gateway behavior in this repository. It is not a protocol requirement that every runtime use these field names.

`executionState: unknown` means the downstream call did not yield a completed or failed HTTP result, or the executor threw after dispatch had begun. The authority path records `decision: ALLOW`, `failureMode: SYSTEM_ERROR`, `execution.outcome: unknown`, and `executed: false`, and consumes the nonce. `executed: false` here means the runtime cannot claim a completed result. It does not mean the external write was proven absent. `not_dispatched` is reserved for a halt before `execute` is called. Reconciliation is a later read of the downstream ledger. It does not POST.

# OUTCOME-UNKNOWN-RECONCILIATION

## Behavior

The downstream server commits the intent hash, then can drop the socket before the HTTP response (`POST /control/drop-next` on loopback inside that container).

The gateway:

1. Records `started` in `adap_execution_log` before the POST.
2. On a dropped connection, classifies the call as `unknown`.
3. Returns that state to the authority path instead of pretending the call did not happen.
4. The nonce is consumed, so the same signed intent cannot be executed again.
5. `GET /v1/reconcile/:intentHash` reads the downstream ledger. It does not POST. It moves `unknown` or `started` to `reconciled`.

## Measured run

| Step | Observation |
| --- | --- |
| Authorize while drop-next was armed | `executionState: unknown`, receipt `executed: false`, `outcome: unknown` |
| Same intent to the other replica | `decision: BLOCK`, `executed` not true |
| `GET /v1/reconcile/{intentHash}` | `state: reconciled`, `detail: downstream_has_one_record` |
| Downstream business writes | 3 after this step (one replay, one approval, one unknown). No second business row for the unknown intent |

The authority receipt's `outcome: unknown` and `executed: false` mean the runtime invoked the executor and cannot claim a completed result. They do not mean the business transaction was known to be committed, and they do not mean it was known to be absent. Reconciliation is what established that the downstream ledger had one record.

A paused Postgres is a different case. The caller timed out, and after unpause the nonce was `consumed`. The retry was `BLOCK`. One commit happened. The caller did not get a second execution.

Automatic retry of an unknown or timed-out non-idempotent call is not implemented.
