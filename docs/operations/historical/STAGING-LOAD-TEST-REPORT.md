> **Historical snapshot.** This file records an earlier audit or local drill. It is not the current state of `main`.
> Notes that name `1fa576a` or `security/adap-complete-remediation` describe that earlier tree.
> Current status: [Security status](../../security/status.md).

# STAGING-LOAD-TEST-REPORT

## Workload

One Docker Desktop host. Two gateway containers, one Postgres 16 container.

Three waves of unique signed `ALLOW` intents, posted concurrently, alternating replicas:

| Wave | Concurrent requests |
| --- | --- |
| 1 | 1 |
| 2 | 8 |
| 3 | 24 |

Total samples: 33. Each nonce was new. This is not a model of production traffic. There is no think time, no mixed `REQUIRE_HUMAN` traffic, and no multi-host network.

## Acceptance threshold

p99 under 2000 ms and zero errors on these fresh intents. The threshold is for this laptop-sized staging stack. A local TLS request plus one Postgres round trip that takes longer than two seconds is treated as a stall. It is not a capacity target for a larger deployment.

## Result

| Metric | Value |
| --- | --- |
| Successes | 33 |
| Errors | 0 |
| p50 | 82 ms |
| p95 | 91 ms |
| p99 | 91 ms |

Threshold met for this workload.

## Resource snapshot after the run

`docker stats --no-stream`:

| Container | CPU | Memory |
| --- | --- | --- |
| gateway-a | 0.01% | 31.8 MiB |
| gateway-b | 0.00% | 29.99 MiB |
| postgres | 1.49% | 59.13 MiB |
| vault | 0.42% | 205.3 MiB |
| downstream | 0.00% | 19.23 MiB |

The snapshot is after the load, not a profile of the peak. No lock-wait error appeared in the 33 requests. Downstream `businessWrites` ended at 38, which matches the successful functional writes plus these 33 intents plus the single write that completed after the paused database resumed.
