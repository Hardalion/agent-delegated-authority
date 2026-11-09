# Baseline audit

Recorded before the sandbox changes, on `origin/hackathon/console` at `953f3dd8cb1836015e82b87bdf04fd9a1ae90514`.

Package version: `agent-delegated-authority` 0.1.0. Node.js v22.19.0. pnpm 10.15.1. The console depends on `adap`, `adap-gateway`, `adap-policy`, `adap-receipt`, and `zod` 4.6.6. Vitest is 4.1.12.

## What the branch was

`apps/hackathon-console` is a loopback HTTP server with a static page. One `DemoRuntime` holds identities, a treasury policy, an in-memory nonce ledger, and an in-process payment map. The authority path is `packages/aap` and `packages/adap-gateway`.

Routes that existed: `GET /api/health`, `GET /api/state`, `GET /api/export`, `POST /api/reset`, `POST /api/receipts/verify`, `POST /api/scenarios/:id`, `POST /api/approvals/:nonce/approve|reject`, `GET /api/receipts/:id/verify`, and four static files. There was no session, no team boundary, and no WebSocket. The approver passphrase defaulted to `treasury-demo`, including in the page.

The payment rail was an in-process object. It did not make an HTTP call. `change_beneficiary` was granted by the delegation and blocked by policy, and the broker did not register that route.

`hackathon-starter.mjs` and `hackathon-starter.ts` called `evaluateToolCall` without `agentRole`. On this branch a missing role is `BLOCK` / `agent_not_in_scope`, including for `read`.

## Tests actually run

Command: `pnpm install --frozen-lockfile`, `pnpm build`, `pnpm test`.

| Package | Result |
|---|---|
| adap-policy | 8 files, 59 passed |
| adap-receipt | 3 files, 19 passed |
| adap | 13 files, 83 passed |
| adap-gateway | 1 file, 7 passed |
| adap-hackathon-console | 5 files, 29 passed, 1 failed |

The failure was `reports OUTCOME UNKNOWN when the simulated rail does not return a result`. The label was `OUTCOME UNKNOWN` and the case `executed` flag was `true`. The kernel sets `executed: true` when the execute callback returns, including when the gateway reports `executionState: 'unknown'`.

## Security boundaries that already existed

Reset refuses `NODE_ENV=production`, refuses `ADAP_PG_URL`, and refuses a database URL that is not local or whose name does not contain `hackathon` or `demo`. Request bodies are Zod-strict and capped at 64KiB. Static files come from an allowlist. The agent module does not call the broker.

## Dependencies on other branches

`hackathon/production-ready` at `9cb404b` contains commit `addccc4` ("Merge execution-semantics fail-closed fixes"). That branch was not used. `origin/security/execution-semantics` is gone. The local worktree `npl-spec` is on `security/execution-semantics` and was not copied.

The unknown-outcome receipt behavior above is the point where a kernel change would overlap that work. It was left unchanged.
