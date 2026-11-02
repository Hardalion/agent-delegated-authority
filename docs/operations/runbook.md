# Operations runbook

Guidance for an operator of the reference gateway. Not a description of a hosted Hardalion service.

# OPERATIONS-RUNBOOK

## Health

- **Liveness:** process up.
- **Readiness:** Postgres `SELECT 1` succeeds AND policy registry hydrated AND vault reachable.
- Fail closed: if readiness fails, refuse new authorizations.

## Common operations

### Rotate receipt issuer key

1. Add new key id to issuer set (retain old for verify).
2. Emit new receipts with new key id.
3. After max receipt lifetime, retire old key.

### Publish policy

1. `registerAsync(policy, uri)` — first content hash wins.
2. Do not mutate in place; publish a new URI for a new document.
3. Revoke old URI only after in-flight pending approvals are drained or expired.

### Replay storm / nonce conflicts

1. Check `replay.attempt` / `nonce.conflict` metrics.
2. Confirm all gateway replicas share one DB.
3. Do not reset `adap_nonces` while intents could replay.

### Downstream `outcome_unknown`

1. Treat as possible commit; do not auto-retry the same intent nonce.
2. Reconcile via downstream idempotency key = intent hash.
3. See `INCIDENT-RESPONSE.md`.
