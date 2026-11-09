# Production readiness

Branch: `hackathon/participant-sandbox`, based on `953f3dd8cb1836015e82b87bdf04fd9a1ae90514`. The commit that contains this file is the tip of that branch. Read it with `git rev-parse HEAD`. This file was written in that commit, so the hash below is the parent baseline, not the tip.

Baseline: `953f3dd8cb1836015e82b87bdf04fd9a1ae90514`.

Commands: `pnpm typecheck`, `pnpm test` (206 passed, 0 failed), `pnpm test:security` (passed), `pnpm audit --audit-level high` (no known vulnerabilities). Node.js v22.19.0. pnpm 10.15.1. Sandbox: Node `node:sqlite` in `services/sandbox-apis/server.mjs`.

Deployment model: one process pair per team. Local bind `127.0.0.1`. Hosted compose is prepared and was not started.

Load: 20 concurrent status calls, 4 waves, one team. p50 109.4 ms, p95 285.1 ms, RSS 132988928, heap 58669736. Zero failures in that sample.

Browser: €120 executed and stored, €750 waited with no new payment, approval stored one €750 payment, €6,000 blocked with the payment count unchanged.

| Requirement | Result |
|---|---|
| Starters pass an explicit agent and show ALLOW, REQUIRE_HUMAN, BLOCK, unknown, missing, and malformed | PASS |
| No default `treasury-demo` credential | PASS |
| Authorized read hits the sandbox | PASS |
| €120 payment persisted | PASS |
| €750 waits, then one payment after approval | PASS |
| Rejected approval does not pay | PASS |
| €6,000 BLOCK and no new payment | PASS |
| Vendor unchanged before approval, one change after | PASS |
| Purchase ALLOW, REQUIRE_HUMAN, and BLOCK | PASS |
| Unknown and malformed agent do not write | PASS |
| Replay does not double the side effect | PASS |
| Concurrent approval creates one payment | PASS |
| Timeout before commit stays unknown and unreconciled to a row | PASS |
| Timeout after commit reconciles one row and does not POST again | PASS |
| Sandbox not accepting writes fails closed without a new payment | PASS |
| Closed port does not report a sandbox execution | PASS |
| Second team's reset does not clear the first team's file | PASS |
| Tampered receipt fails verification | PASS |
| Team session required for state and reset | PASS |
| Public bind refused unless `ADAP_CONTAINER=1` | PASS |
| Unknown downstream result is ALLOW, `executed: false`, and not retried | PASS |
| Docker image build, non-root user, loopback publish, health, ready, €120 stored, €6,000 blocked | PASS |
| GitHub Actions on `hackathon/participant-sandbox` | PASS for commit `c29abed`. Latest run: https://github.com/Hardalion/agent-delegated-authority/actions/runs/42690887932 |
| HTTPS proxy | NOT TESTED |
| Postgres suite in CI | PASS (`postgres-integration` on that run) |
| Backup file restore drill | NOT TESTED |
| Event-sized load beyond 20-wide on one instance | NOT TESTED |

## Launch status

Unknown receipts and the hosted compose drill are fixed on this commit. The compose stack was built from `apps/hackathon-console/Dockerfile`, ran as user `adap`, published only `127.0.0.1:4317` and `127.0.0.1:4318`, returned health and readiness, stored one €120 sandbox payment, and left the €6,000 request blocked with that single committed payment. The stack was then stopped.

GitHub Actions on this branch passed for commit `c29abed`: https://github.com/Hardalion/agent-delegated-authority/actions/runs/42690887932. Do not merge to `main`. Do not publish the host port beyond loopback. HTTPS in front of the proxy was not part of this drill.
