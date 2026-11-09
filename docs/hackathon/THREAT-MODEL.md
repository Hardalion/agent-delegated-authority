# Threat model

The sandbox is a hackathon system. The assets are team state, approver decisions, sandbox rows, and receipts. It is not a bank connector.

## Actors

Participants on one team, participants on another team, and the event operator. The agent is the treasury identity inside the console. A caller that names a different agent is rejected and the sandbox is not called.

## Boundaries

| Boundary | Control |
|---|---|
| Browser to console | Team session cookie, 8 hour expiry, logout and reset revoke it |
| Cookie mutations | `x-adap-request: 1` and same-host `Origin` |
| Console to sandbox | Bearer token held by the adapter. The page never receives it |
| Sandbox URL | Operator-configured. HTTP is loopback or a single-label service name. Redirects are errors. Link-local and `metadata` hosts are rejected |
| Reset | Confirmation phrase, approver passphrase, session, and a demo database path |
| Static files | Allowlist. No path join from the request |
| Body and headers | 64KiB body, header JSON capped at 16KiB, rate limit default 120/minute |
| Errors | `{ error: { code, message } }`. No stack traces |

## What this does not claim

A correct deployment still depends on the host firewall and the proxy. Binding `0.0.0.0` inside a container is reachable by anyone who can reach that network namespace. The compose file publishes loopback only. That publish rule was not verified with a running Docker daemon.

The signed receipt can say executed when the downstream outcome is unknown. See the architecture note. Verification of a tampered receipt fails. That test passed.

Secrets are redacted from the export assertion in the sandbox test (team sandbox token, approver passphrase, and `PRIVATE KEY` were absent). A repository-wide secret scanner beyond `pnpm audit` and the CI private-key grep was not added.
