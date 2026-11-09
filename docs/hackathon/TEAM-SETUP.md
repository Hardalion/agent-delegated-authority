# Team setup

Use one operating-system process pair per team. Do not point two teams at the same `SANDBOX_DB` file or the same console port.

## Local

Each team clones the repo and runs `pnpm hackathon:start`. State stays on that machine. The team token and approver passphrase are different for every process that does not set them.

## Hosted event

For each team, on the event host:

1. Choose a team id such as `team-01`.
2. Generate three secrets of at least 24, 16, and 32 characters. Do not reuse `treasury-demo`.
3. Generate a sandbox token of at least 16 characters.
4. Start the sandbox with `SANDBOX_DB` set to a path that contains `hackathon` or `demo`, for example `/data/team-01-hackathon.sqlite`.
5. Start the console with `ADAP_DEPLOYMENT=hosted`, that team's secrets, and `ADAP_SANDBOX_URL` pointed only at that team's sandbox.
6. Bind the console to loopback. Terminate HTTPS on a reverse proxy. Publish host ports as `127.0.0.1` only.
7. Give the team the console URL, the team token, and the approver passphrase through a channel outside the repository.

A session cookie is HttpOnly, SameSite=Strict, and expires after 8 hours. Hosted mode sets `Secure` unless `ADAP_COOKIE_SECURE=0` for a local TLS test. Logout and reset revoke the process's sessions.

The container image runs as uid 10001. Secrets are environment variables, not image layers. `deploy/hackathon/docker-compose.yml` is a single-team example. It was not started against a public host in this change.
