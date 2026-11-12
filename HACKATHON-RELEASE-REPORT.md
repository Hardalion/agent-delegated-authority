# ADAP Hackathon Participant Release Report

Date: 2026-11-12  
Branch: `hackathon/participant-release-2026-11-11`  
Baseline: `origin/hackathon/participant-sandbox` @ `8c398e0`  
Release commits on this branch (relative to baseline):

1. `1b2f7208be2b65298fd75ad95be1e894a55d94f4` — Harden the Gen AI Summit participant sandbox for event production.
2. `e1b925095ec0528a547c7ba139ec15652b2fa60c` — Record the release candidate commit hash in the report.

Pre-event closure commit (this write-up and follow-ups) is recorded below after it is created.  
Hardening commit `1b2f720…` is an ancestor of HEAD (**PASS**).

This is an event-production release candidate for synthetic hackathon use. It is not approval for real banking or production enterprise writes.

## Final approval scopes

| Scope | Decision | Basis |
|---|---|---|
| A. Local participant installations | **APPROVED** | Fresh-install path, suites, durable restart, SQLite backup/restore |
| B. Central hosted event deployment | **APPROVED WITH CONDITIONS** | 3-team Compose PASS; mkcert-trusted TLS browser E2E PASS; operators must use a trusted cert, preserve public `Host` on the reverse proxy, and set a valid base64url 32-byte `ADAP_STATE_ENCRYPTION_KEY` |
| C. Real enterprise execution | **NOT APPROVED** | Synthetic sandbox only |

Do not conflate A, B, and C.

## Pre-event closures (2026-11-12)

### 1. Human approval identity — VERIFIED (shared-secret gate, not independent human IdP)

| Claim | Result |
|---|---|
| Approve route requires team session (or team bearer) | **PASS** — anonymous → 401 `auth_required` |
| Wrong passphrase rejected without execution | **PASS** — 401 `approver_rejected`; pending remains |
| Correct passphrase mints `HumanApproval` as `prn_treasury` | **PASS** — protocol requires `approver_id === principal` |
| Distinct human OIDC / personal approver key | **NOT PRESENT** — expected for this event sandbox |
| Evidence | `apps/hackathon-console/src/approval-identity.test.ts` (**PASS**, 4 tests) |

Honest model: team session + shared approver passphrase authorize the console to sign as the treasury principal. The browser does not hold the principal key. This is a human *role gate*, not an independently authenticated person identity.

### 2. Trusted-TLS interactive browser — PASS

| Check | Result |
|---|---|
| mkcert local CA installed in Windows trust store | **PASS** |
| Compose hosted console on `127.0.0.1:4527` | **PASS** |
| HTTPS proxy `https://127.0.0.1:8443` with mkcert cert | **PASS** |
| IDE Chromium loads UI without cert interstitial | **PASS** (previously **BLOCKED** on self-signed) |
| Secure session cookie login | **PASS** |
| UI: Pay €750 → REQUIRE_HUMAN, payments unchanged | **PASS** |
| UI: Approve with passphrase → one additional payment | **PASS** (3 → 4) |
| API path: ALLOW / REQUIRE_HUMAN / approve / BLOCK | **PASS** |
| Reverse proxy must preserve public `Host` | **PASS** after fix; rewriting Host to upstream breaks Origin checks |

Operator note added in `docs/hackathon/OPERATOR-RELEASE.md`.

### 3. Clean installation — see section 12

Recorded after push of this branch.

## 1. Release identity verification

| Check | Result |
|---|---|
| Branch | `hackathon/participant-release-2026-11-11` |
| Baseline relative commits | Exactly the two listed above before the pre-event closure commit |
| `1b2f720…` ancestor of HEAD | **PASS** |

## 2. Gates

| Gate | Result | Notes |
|---|---|---|
| A Security | **PASS** | Trusted roots; fail-closed numerics; cross-team rejection; Secure cookies; approval identity model documented |
| B Reliability | **PASS** | Durable SQLite; backup/restore; pending recovery; reconcile without duplicate |
| C Participant UX | **PASS** | Sandbox scenarios; EUR; i18n |
| D Deployment | **PASS** | 3-team Compose; trusted-TLS browser E2E |
| E Testing | **PASS** with listed skips | See section 7 |

## 3. SQLite backup and restore drill

| Check | Result |
|---|---|
| Overall | **PASS** |

Evidence: `%TEMP%/adap-release-verify/logs/sqlite-backup-restore.json`

## 4. Hosted TLS authentication

| Check | Result |
|---|---|
| Scripted HTTPS Secure/HttpOnly/SameSite cookie auth | **PASS** |
| Interactive Chromium with self-signed cert | **BLOCKED** (historical) |
| Interactive Chromium with mkcert-trusted cert | **PASS** (pre-event closure) |

Evidence: `%TEMP%/adap-release-verify/logs/tls-auth.json` plus this report’s browser section.

## 5. Multi-team Compose drill

| Check | Result |
|---|---|
| Overall (3 teams, isolation, restart) | **PASS** |

Evidence: `%TEMP%/adap-release-verify/logs/multi-team.json`

## 6. Process-restart test review

| Test | Result |
|---|---|
| Durable reopen restores pending; approve once | **PASS** |
| Timeout-before / timeout-after reconcile without duplicate | **PASS** |
| SQLite backup/restore approve once + replay reject | **PASS** |

## 7. Release commands on HEAD `e1b9250` (pre-closure)

| Command | Result |
|---|---|
| `pnpm build` | **PASS** |
| `pnpm typecheck` | **PASS** |
| `pnpm test` | **PASS** |
| `pnpm test:security` | **PASS** |
| `pnpm hackathon:test` | **PASS** (53 tests at that HEAD) |
| `pnpm smoke` | **PASS** |
| `pnpm attacks` | **PASS** |
| `node scripts/hackathon-load-test.mjs` | **PASS** — samples=200; p50=1.7 ms; p95=3.1 ms; errors=0 |
| `pnpm test:integration:postgres` | **BLOCKED** — `ADAP_PG_URL` unset |
| `approval-identity.test.ts` (closure) | **PASS** (4 tests) |

Load sample is synthetic concurrent authorize work. It is not capacity proof for hundreds of concurrent human browsers.

## 8. Remaining limitations

1. Sessions remain in-memory; restart requires re-login.
2. Approver identity is a shared passphrase + principal signature, not an IdP human subject.
3. Hosted Secure cookies require TLS; reverse proxy must preserve the public `Host`.
4. Postgres integration suite not on the participant path.
5. Do not merge to `main` without a separate decision.
6. Encryption keys must be base64url-encoded 32 bytes.

## 9. Participant startup

```bash
git clone https://github.com/Hardalion/agent-delegated-authority.git
cd agent-delegated-authority
git checkout hackathon/participant-release-2026-11-11
pnpm install --frozen-lockfile
pnpm hackathon:start
```

Open `http://127.0.0.1:4317`. See `docs/hackathon/PARTICIPANT-RELEASE.md`.

## 10. Operator deployment

See `docs/hackathon/OPERATOR-RELEASE.md`. One Compose project per team; trusted TLS; preserve `Host`; valid `ADAP_STATE_ENCRYPTION_KEY`.

## 11. Ported from `fix/verified-issues-3-4-6-7`

Fail-closed numeric comparisons and related evaluator hardening. Not blindly merged: DEFER/SIMULATE schema removal and unrelated gateway mass-deletes.

## 12. Clean installation drill

Status: **PENDING** until this branch is pushed, then re-run from a fresh clone with no prior `.demo` or `node_modules`. Result will be appended in the commit that lands the push confirmation, or recorded here as:

| Check | Result |
|---|---|
| Fresh clone + checkout + `pnpm install --frozen-lockfile` + `pnpm hackathon:start` | *to be filled after push* |

## Verification hygiene

- Pre-event closure added approval-identity tests and operator Host-header guidance. No authority-kernel redesign.
- Compose browser-tls stack and mkcert proxy were stopped after the drill.
- No merge to `main`.
