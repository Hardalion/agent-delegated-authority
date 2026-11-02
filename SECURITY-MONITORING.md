# SECURITY-MONITORING

Emit structured events from `adap-gateway` (`SecurityEventSink`). Never include secrets or full parameter blobs.

## Required events

| Event | Alert hint |
| --- | --- |
| `authorization.allow` | Rate / anomaly baseline |
| `authorization.require_human` | Queue depth |
| `authorization.block` | Spike investigation |
| `signature.invalid` | Page on sustained elevation |
| `replay.attempt` | Page on multi-instance spike |
| `policy.mismatch` | Page |
| `approval.accepted` / `rejected` / `expired` | Audit |
| `nonce.conflict` | Correlate with replay |
| `execution.started` / `completed` / `failed` / `outcome_unknown` | SLO + incident |
| `receipt.verify_failure` | Page |
| `admin.policy_change` | Audit trail |
| `key.rotation` | Audit |
| `storage.failure` | Page readiness |

## Metrics (minimum)

- authz decisions by type
- nonce CAS failure rate
- downstream latency / unknown rate
- Postgres pool wait / errors

## Correlation

Every gateway request gets `correlationId`. Propagate as `x-adap-correlation-id` to downstream.
