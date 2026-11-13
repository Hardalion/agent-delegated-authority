# ADAP Hackathon Participant Guide

English default. Greek is available in the console language switcher.

## Public pack

1. [HACKATHON-QUICKSTART.md](./HACKATHON-QUICKSTART.md)
2. This guide
3. [ADAP-FRAMEWORK-INTEGRATION.md](./ADAP-FRAMEWORK-INTEGRATION.md)
4. Protocol: [../spec/](../spec/)

## Mindset

ADAP decides whether an agent action is within delegated authority. It does **not** replace your agent framework, model, or product.

For this event, **ADAP and your agent both run on your machine**.

## Setup

```bash
git clone --branch hackathon/participant-release-2026-11-11 --single-branch https://github.com/Hardalion/agent-delegated-authority.git
cd agent-delegated-authority
pnpm install --frozen-lockfile
pnpm hackathon:start
```

Open `http://127.0.0.1:4317`.

| Credential | Use |
|---|---|
| **Team token** (printed once at startup) | Console login **and** `Authorization: Bearer` for local `/api/gate` |
| **Approver passphrase** | Only for REQUIRE_HUMAN in the browser treasury demo |

One Team token for UI and API. It is a local sandbox credential, not a production identity. Do not commit it or send it to external hosted agents.

Use agent id `agt_hackathon_demo` everywhere. **Do not edit** `weekend-gate.ts`.

Sandbox: `sandbox: true`, `realMoney: false`.

## Two complementary demos

### A. Signed ADAP sandbox (browser)

Treasury scenarios exercise the signed intent / policy / receipt path:

| Scenario | Result |
|---|---|
| pay-120 | ALLOW + synthetic execution + receipt |
| pay-750 | REQUIRE_HUMAN → approve with passphrase → single execution → replay rejected |
| pay-6000 | BLOCK + no execution |

### B. Framework-neutral policy decision API (`/api/gate`)

For plugging **any** agent framework. See [ADAP-FRAMEWORK-INTEGRATION.md](./ADAP-FRAMEWORK-INTEGRATION.md).

| Tool | Decision |
|---|---|
| `search_web` | ALLOW |
| `send_email` | REQUIRE_HUMAN |
| `delete_record` | BLOCK |

Mock your tools. Do not connect real email, Slack, CRM, or payment systems.

`/api/gate` does not run your tool and is not the full signed-delegation authority path. The browser sandbox is where you see full approval + receipt semantics for payments.

## Protocol

Normative text: [../spec/](../spec/).

This console is a synthetic reference sandbox, not a certification of your production system.

## Stop

In the terminal where `pnpm hackathon:start` is running, press `Ctrl+C`.

## Out of scope for participants

You do **not** need Docker, hosted deployment, DNS, TLS, organizer team IDs, PostgreSQL, Vault, or manual encryption keys to start.
