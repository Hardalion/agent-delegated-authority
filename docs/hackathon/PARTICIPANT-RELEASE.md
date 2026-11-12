# Participant release guide

Branch: `hackathon/participant-release-2026-11-11`.

This is an event sandbox. Synthetic EUR records only. No real payments. No production credentials.

## Requirements

- Node.js 22+
- pnpm 10.15+

## Fresh install

```bash
git clone https://github.com/Hardalion/agent-delegated-authority.git
cd agent-delegated-authority
git checkout hackathon/participant-release-2026-11-11
pnpm install --frozen-lockfile
pnpm hackathon:start
```

Open `http://127.0.0.1:4317`. Paste the printed team token. Use the printed approver passphrase only when a decision is waiting for a person.

## What you will see

| Scenario | Expected |
|---|---|
| Authorized read | ALLOW, sandbox record returned |
| Pay €120 | ALLOW, one synthetic `pay_` row |
| Pay €750 | REQUIRE_HUMAN, no new payment until approve |
| Approve | One payment for the original intent |
| Pay €6,000 | BLOCK, payment count unchanged |
| Vendor change | REQUIRE_HUMAN |
| Restricted purchase | BLOCK |
| Receipt verify | Server runs `adap.verifyProtocolReceipt` |
| Unknown outcome | Reconcile. Do not resubmit the same intent |

The in-page presentation uses those sandbox scenario ids when the rail is the local sandbox API.

## Agent plug-in

Open `/guide` for the weekend gate. Research tools such as `search_web` are allowed. Side effects wait for a person. Deletes and payment tools are blocked. Examples live under `examples/hackathon/`.

## Evidence and reset

1. Export evidence from the console or `GET /api/export`.
2. Reset only after export succeeds. Reset writes evidence under `.demo/exports`, verifies the file, then clears sandbox and operational state.
3. If export fails, reset does not run.

## Stop

Ctrl+C. Durable console state, if enabled, stays under `.demo/state/` for the next start.

## Limits

This is not approval for real banking. One console process serves one team. Hosted deployments bind the published port to loopback and keep the sandbox on an internal network.
