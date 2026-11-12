# Operator release guide

One Compose project per team. Loopback publish only. Synthetic data only.

## Per-team environment

Generate independent secrets outside the repo:

```bash
export COMPOSE_PROJECT_NAME=adap-team-alpha
export ADAP_TEAM_ID=team-alpha
export ADAP_TEAM_TOKEN="$(openssl rand -base64 32)"
export ADAP_APPROVER_PASSPHRASE="$(openssl rand -base64 24)"
export ADAP_SESSION_SECRET="$(openssl rand -base64 48)"
export ADAP_SANDBOX_TOKEN="$(openssl rand -base64 32)"
export ADAP_STATE_ENCRYPTION_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
export CONSOLE_HOST_PORT=4317
```

Deploy:

```bash
docker compose -f deploy/hackathon/docker-compose.yml up --build -d
```

- Console published as `127.0.0.1:${CONSOLE_HOST_PORT}`
- Sandbox is not published on the host; console reaches it as `http://sandbox:4318`
- Volume `hackathon-data-${ADAP_TEAM_ID}` holds sandbox SQLite and durable console state
- `ADAP_COOKIE_SECURE=1` requires a TLS reverse proxy in front of the loopback listener

Health: `GET /api/health`. Ready: `GET /api/ready`.

## Trusted roots (gateway path)

If you run the staging gateway, set `ADAP_TRUSTED_ROOT_ISSUERS` to the operator principal ids. A key in the directory alone does not establish root authority.

## Backup and restore

Do not copy a live SQLite file while WAL is open as an ordinary file copy.

Safe pattern:

```bash
# From a stopped stack, or using sqlite3 .backup against a quiesced DB:
sqlite3 /path/to/team.sqlite ".backup '/path/to/team.backup.sqlite'"
```

Restore only after the console and sandbox for that team are stopped. Replace the team files, then start the Compose project again. Verify `/api/ready` and one read scenario.

## Restart recovery

Durable console state persists identities, nonces, pending approvals, cases, receipts, and execution lifecycle markers under `/data/state`. Pending approvals survive process restart when the encryption key and state directory are unchanged. Unknown downstream outcomes stay unresolved until reconcile. Do not auto-retry.

## Isolation incidents

If team A’s cookie or bearer token reaches team B’s console, expect 401. Confirm distinct `COMPOSE_PROJECT_NAME`, host port, tokens, encryption key, and volume. Stop any shared process that was started by mistake.

## Reset

Reset exports evidence first, verifies the file, then resets the sandbox. If export fails, reset aborts.
