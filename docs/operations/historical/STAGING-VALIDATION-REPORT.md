> **Historical snapshot.** This file records an earlier audit or local drill. It is not the current state of `main`.
> Notes that name `1fa576a` or `security/adap-complete-remediation` describe that earlier tree.
> Current status: [Security status](../../security/status.md).

# STAGING-VALIDATION-REPORT

## Re-run 2026-11-02

Command: `node staging/scripts/run-validation.mjs`. Exit 0. Script summary: 37 passed, 0 failed. This is a local Docker Compose drill, not production validation.

Recorded differences from the 2026-11-01 drill:

- Backup dump 231 ms, restore 325 ms.
- Load: 33 unique intents, 0 errors, p99 90 ms.
- Agent curls to downstream and Vault exited 28. The check accepts any non-zero exit, so this run does not repeat the earlier exit 6 result.
- Connection exhaustion still returned `executed: true` while new clients received `sorry, too many clients already`. The script check stays true when that error string is present, so it is not proof that an already-connected gateway fails closed.

## Earlier drill

Run finished `2026-11-01T21:23:50.752Z`. Command: `node staging/scripts/run-validation.mjs` from `npl-spec`. Result: **37 checks recorded, 0 failed by the script**. Exit code 0. Evidence: `staging/.evidence/summary.json`.

HEAD at the run: `1fa576a8ef4a889685d5623d67c9ae71366c8f2d`. That commit is also the tip of `security/adap-complete-remediation`. The working tree was checked out as `hackathon/genai-summit` when last inspected; that name points at the same commit. Nothing was committed.

## What passed

| Check | Result |
| --- | --- |
| Compose up, both gateways ready | TLS on 8443 and 8444 |
| Same intent to both replicas | One `executed: true`, one `BLOCK`. Nonce row `consumed`. Downstream business writes: 1 |
| Alert | `replay.attempt` received by the alert sink |
| `REQUIRE_HUMAN` | Decision returned. After `docker compose restart` of both gateways, `adap_pending.approval_state` was still `pending` |
| Concurrent approval | One `ALLOW`/`executed: true`, one `BLOCK` |
| Dropped downstream response | `executionState: unknown`, `executed: true`. Retry `BLOCK`. Reconcile state `reconciled`, detail `downstream_has_one_record`. Business writes stayed 3 |
| Vault rotation | Old rail token `401`, new token `200`. Next authorize `ALLOW` |
| Responses and logs | Rail token, client token, and Vault root token were absent |
| Agent network | Gateway health `200`. Downstream and Vault curl exit 6. Authorize without the client token `401` |
| Postgres pause | Caller timed out (`client_timeout`). After unpause, retry of that nonce was `BLOCK`. The nonce row was `consumed` |
| Postgres restart | Gateways became ready again. Consumed nonce still `consumed` |
| Backup / restore | `pg_dump` 285 ms, restore 381 ms. Restored nonce `consumed`. Restored approval row `consumed` (the approval had already completed before the dump) |
| Lock | `LOCK TABLE adap_nonces` then authorize returned `BLOCK`, not executed |
| Interrupted insert | `pg_terminate_backend` during an open transaction. Count for `interrupt-nonce` was 0 |
| Statement timeout | `SET statement_timeout = '50ms'; SELECT pg_sleep(1)` exited 1 |
| Migration rollback | Scratch database `adap_drill`. Tables present before rollback, none after |
| Load | 33 unique intents, 0 errors. p50 82 ms, p95 91 ms, p99 91 ms |
| Alerts at the end | `replay.attempt`, `execution.outcome_unknown`, `storage.failure` |

Downstream business-write count at the end: 38. That is the functional writes plus the 33 load intents plus the one write that completed after the paused database resumed.

## What the green exhaustion check does not prove

`connection-exhaustion-not-allow` is `ok: true` in the JSON because the harness saw `sorry, too many clients already` **or** a non-execution. The same record says the gateway response was HTTP 200, `executed: true`. The replica already held a pooled connection, so it still authorized while new clients were refused. Connection exhaustion did not fail that replica closed.

## Postgres assumptions

One writable primary. `docker pause` freezes the database process, including its timers, so an in-flight statement can still commit when the process resumes. The consumed nonce then blocks a second execution. This stack has no replica promotion and no split-brain control.
