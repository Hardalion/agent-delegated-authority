# Integration test report

Date: 2026-11-09. Machine: Windows, Node.js v22.19.0, pnpm 10.15.1. Sandbox: `services/sandbox-apis/server.mjs` using `node:sqlite` (experimental warning on this Node build). No Docker daemon was running.

## Commands

```text
pnpm typecheck
pnpm test
pnpm test:security
pnpm audit --audit-level high
```

`pnpm test` result:

| Package | Tests |
|---|---|
| adap-policy | 59 passed |
| adap-receipt | 19 passed |
| adap | 83 passed |
| adap-gateway | 7 passed |
| adap-hackathon-console | 38 passed |

206 passed, 0 failed. `pnpm test:security` passed (policy fail-closed 12, adap adversarial files 66, receipt semantics 3, gateway 7). `pnpm audit --audit-level high` reported no known vulnerabilities.

The console file `src/sandbox.integration.test.ts` starts two real sandbox processes and two SQLite files. It is included in the 38.

## Load sample from that file

`LOAD team-b status waves=4 width=20 samples=80 p50=109.4 p95=285.1 rss=132988928 heap=58669736`

Eighty status reads, offered as 20 at a time, on one team runtime. That runtime serializes authority, so the times include queue wait. No error was asserted in that sample. RSS was about 127 MB at the end of the sample. This is not a capacity test for an unnamed event size.

## Browser

A local console on `127.0.0.1:4317` with the sandbox on `4318` was driven in a browser.

- Signed in with the team token. The sandbox label was "Connected to the local sandbox API. Records are synthetic and persisted by that API. No real money moves."
- Pay €120 showed EXECUTED and a persisted `pay_` row for €120.00.
- Pay €750 showed NOT EXECUTED · AWAITING APPROVAL while payments created stayed at 1.
- Approve created one €750.00 row. Payments created became 2.
- Pay €6,000 showed NOT EXECUTED · BLOCKED. Payments created stayed 2.

## Not run

GitHub Actions on this commit. Docker Compose. Postgres `pnpm test:integration:postgres`. An HTTPS proxy. A file-level backup restore. A load test larger than the 20-wide sample.
