# ADAP Hackathon Participant Release Report

Date: 2026-11-12  
Branch: `hackathon/participant-release-2026-11-11`  
Baseline: `origin/hackathon/participant-sandbox` @ `8c398e0`  
Release candidate tip: run `git rev-parse HEAD` on this branch. Hardening commit: `1b2f7208be2b65298fd75ad95be1e894a55d94f4`.

This is an event-production release candidate for synthetic hackathon use. It is not approval for real banking or production enterprise writes.

## 1. Release branch

`hackathon/participant-release-2026-11-11`

## 2. Gates

| Gate | Result | Notes |
|---|---|---|
| A Security | **PASS** (verified in tests) | Trusted root issuers required on authority path; fail-closed numeric comparisons; policy pin unchanged; cross-team cookie/bearer/sandbox-token rejection tested |
| B Reliability | **PASS** (verified in tests + compose drill) | Durable SQLite state; evidence-before-reset; timeout classification fixed; unknown outcomes not auto-retried |
| C Participant UX | **PASS** | Sandbox guide ids (`pay-120` …); EUR limits; i18n + guide retained |
| D Deployment | **PASS** (compose drill) | Per-team volume; sandbox unpublished; loopback console; Secure cookies; health/ready healthy; €120 ALLOW / €6k BLOCK via bearer |
| E Testing | **PASS** with noted skips | See section 7 |

## 3. Security improvements

- Operator-configured `trustedRootIssuers` required by `runAuthorityPath`. Directory key + signature alone no longer establish root authority.
- Adversarial trusted-root tests in `packages/aap/src/trusted-root.test.ts`.
- Policy engine: `NumericComparisonError` / non-finite comparisons fail closed (ported from verified fix branch, without removing DEFER/SIMULATE from the schema).
- Session rate limits keyed by session/bearer fingerprint; login abuse still IP-keyed.
- Hosted cookies default Secure (`ADAP_COOKIE_SECURE=1`); TLS reverse proxy required for browser cookie login.
- Sandbox no longer published on the host in Compose; console reaches it on the internal network.
- Private keys encrypted at rest in the durable store (AES-256-GCM). Hosted requires `ADAP_STATE_ENCRYPTION_KEY`.

## 4. Reliability improvements

- Per-team SQLite durable store: identities, nonces, pending approvals, cases, timeline, receipt meta, execution lifecycle.
- Reset exports and verifies evidence before sandbox reset.
- `HttpSandboxAdapter` preserves fault mode for timeout-before / timeout-after / unknown classification.
- Execution lifecycle hooks record started / unresolved / completed without automatic retry.

## 5. Participant UX improvements

- Sandbox presentation guide uses `pay-120`, `pay-750`, `pay-6000`, `vendor-change`, `purchase-block`.
- EUR limits exposed in sandbox mode.
- 429 backoff in the console client.
- Participant and operator docs added.

## 6. Files changed (high level)

- `packages/aap` — trusted roots, identity key import/export
- `packages/policy-engine` — fail-closed numeric evaluation
- `packages/adap-gateway` — trusted roots env for staging gateway
- `apps/hackathon-console` — durable store, runtime wiring, security, timeout fix, guide, weekend gate, tests
- `deploy/hackathon/docker-compose.yml` — multi-team volumes, unpublished sandbox, Secure cookies, encryption key
- `docs/hackathon/*`, `examples/smoke-policy.mjs`, `scripts/hackathon-load-test.mjs`
- Participant examples under `examples/hackathon/` (LangChain / CrewAI / AutoGen hooks)

## 7. Test commands and results

| Command | Result |
|---|---|
| `pnpm build` | **PASS** |
| `pnpm typecheck` | **PASS** |
| `pnpm test` | **PASS** (policy, receipt, adap, gateway, hackathon-console) |
| `pnpm test:security` | **PASS** |
| `pnpm hackathon:test` | **PASS** (included in console suite: 53 tests) |
| `pnpm smoke` | **PASS** |
| `pnpm attacks` | **PASS** |
| `node scripts/hackathon-load-test.mjs` | **PASS** — 10 teams × 5 clients × 4 rounds; samples=200; p50=1.8 ms; p95=3.4 ms; errors=0; 429=0; rss≈74.8 MB |
| `pnpm test:integration:postgres` | **BLOCKED** — `ADAP_PG_URL` unset in this environment |
| Compose drill | **PASS** — build, health, ready, pay-120 ALLOW executed, pay-6000 BLOCK, payments=1; then `down -v` |
| SQLite `.backup` restore drill | **NOT TESTED** in this run (operator procedure documented) |
| Browser cookie login behind TLS | **NOT TESTED** (Secure cookies refuse cleartext HTTP cookie replay; bearer path verified) |

## 8. Load-test measurements

```text
LOAD teams=10 clients=5 rounds=4 samples=200 p50=1.8 p95=3.4 errors=0 429=0 rss=74813440 heap=22721904
```

HTTP `/api/state` against isolated in-process consoles. Not a claim about venue Wi-Fi or a shared reverse proxy capacity.

## 9. Deployment drill

- Project: `adap-release-drill`
- Console: `127.0.0.1:4417` healthy
- Sandbox: internal only, healthy
- Volume: `hackathon-data-team-drill`
- Bearer `pay-120` → ALLOW, `pay_…` resource
- Bearer `pay-6000` → BLOCK, `paymentsCreated=1`
- Stack stopped with volumes removed after the drill

## 10. Remaining limitations / blockers

1. In-memory sessions: restart requires re-login even with durable authority state.
2. Secure cookies need TLS in front of the loopback listener for browser cookie auth; bearer works over HTTP loopback for operator checks.
3. Postgres store suite not run here (`ADAP_PG_URL` missing). Hackathon path does not use Postgres.
4. SQLite-aware backup/restore was documented, not executed as a timed drill in this run.
5. Do not merge to `main`. Do not publish ports beyond loopback.
6. Event load beyond the synthetic profile above was not claimed.

## 11. Participant startup

```bash
git checkout hackathon/participant-release-2026-11-11
pnpm install --frozen-lockfile
pnpm hackathon:start
```

Open `http://127.0.0.1:4317`. See `docs/hackathon/PARTICIPANT-RELEASE.md`.

## 12. Operator deployment

See `docs/hackathon/OPERATOR-RELEASE.md`. One Compose project per team; require all secrets including `ADAP_STATE_ENCRYPTION_KEY`; publish only `127.0.0.1:${CONSOLE_HOST_PORT}`; terminate TLS in front of the console for Secure cookies.

## Ported from `fix/verified-issues-3-4-6-7`

- Fail-closed numeric comparisons (`NumericComparisonError`)
- Related evaluator/engine hardening
- Not blindly merged: schema removal of DEFER/SIMULATE, doc mass-deletes, unrelated gateway changes beyond trusted-root wiring
