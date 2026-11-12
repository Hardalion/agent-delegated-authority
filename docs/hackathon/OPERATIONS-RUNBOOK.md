# Operations runbook

Do not start this against a public interface until the operator has reviewed the known limitations and chosen how unknown receipts are explained to participants.

## Start and stop

Local: `pnpm hackathon:start`. Stop with Ctrl+C. The console closes the HTTP server on SIGINT and SIGTERM, then exits.

Hosted, one team: generate secrets outside the repo (including `ADAP_STATE_ENCRYPTION_KEY`), export them, and run `docker compose -f deploy/hackathon/docker-compose.yml up --build` only after the daemon is available and the console publish line still says `127.0.0.1`. The sandbox port is not published on the host. See `docs/hackathon/OPERATOR-RELEASE.md`.

Health: `GET /api/health` returns `{ ok: true }` with no secrets. Readiness: `GET /api/ready` returns 200 only when the sandbox answers `/ready`.

## Reset and recovery

`pnpm hackathon:reset` requires the team token and the approver passphrase. It exports evidence under `.demo/exports`, verifies the file, then resets that process's sandbox file and durable operational state. Identities remain. It does not open `ADAP_PG_URL`.

Durable console state lives under `.demo/state/` (local) or `/data/state` (hosted). Pending approvals and nonces survive a process restart when the encryption key is unchanged.

To roll back a bad console build, stop the process and check out the previous commit on the release branch. SQLite files under `.demo/` or `/data` remain until reset. Backup with `sqlite3 file ".backup '...'"` against a quiesced database; do not treat a live WAL copy as a restore image.

## Incidents

| Signal | Action |
|---|---|
| Readiness 503 | The sandbox process is down or writes are paused. Do not tell participants the payment was blocked by policy |
| OUTCOME UNKNOWN | Open reconcile. Do not click the scenario again for the same nonce. A new nonce is a new payment |
| Auth denied spike | Check the team token and the rate limit. The log line has the team id and path, not the token |
| Suspected cross-team access | Confirm each team has its own port, token, and database file. Stop the shared process if one was started by mistake |

Sessions last 8 hours. Reset revokes them. There is no central session store across processes.

## Secrets

Keep tokens in the environment or the host secret store. `.env.example` is placeholders. Do not commit `.demo/` or a sqlite file from an event.
