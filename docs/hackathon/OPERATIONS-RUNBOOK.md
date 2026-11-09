# Operations runbook

Do not start this against a public interface until the operator has reviewed the known limitations and chosen how unknown receipts are explained to participants.

## Start and stop

Local: `pnpm hackathon:start`. Stop with Ctrl+C. The console closes the HTTP server on SIGINT and SIGTERM, then exits.

Hosted, one team: generate secrets outside the repo, export them, and run `docker compose -f deploy/hackathon/docker-compose.yml up --build` only after the daemon is available and the publish lines still say `127.0.0.1`. This compose file was not executed here.

Health: `GET /api/health` returns `{ ok: true }` with no secrets. Readiness: `GET /api/ready` returns 200 only when the sandbox answers `/ready`.

## Reset and recovery

`pnpm hackathon:reset` requires the team token and the approver passphrase. It exports evidence under `.demo/exports`, then resets that process's sandbox file and memory. It does not open `ADAP_PG_URL`.

To roll back a bad console build, stop the process and check out the previous commit on `hackathon/participant-sandbox`. SQLite files under `.demo/` or `/data` remain until reset. Copy the sqlite file aside before a reset if the team needs the rows. A restore drill that copied a file back and restarted was not run.

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
