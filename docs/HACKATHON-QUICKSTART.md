# ADAP Hackathon Quickstart

**Branch:** `hackathon/participants`
**Full guide:** [HACKATHON-PARTICIPANT-GUIDE.md](./HACKATHON-PARTICIPANT-GUIDE.md)
**Connect any agent:** [ADAP-FRAMEWORK-INTEGRATION.md](./ADAP-FRAMEWORK-INTEGRATION.md)
**Protocol:** [../spec/](../spec/)

ADAP is an **authority and policy interface**, not an agent framework. Your agent runs on **your laptop**. ADAP returns ALLOW, REQUIRE_HUMAN, or BLOCK.

Synthetic sandbox only (`sandbox: true`, `realMoney: false`). No real payment rails. No Docker, DNS, or organizer-issued team IDs.

## 1. Clone and start

Node.js 22+ and [pnpm](https://pnpm.io/) 10+:

```bash
git clone --branch hackathon/participants --single-branch https://github.com/Hardalion/agent-delegated-authority.git
cd agent-delegated-authority
pnpm install --frozen-lockfile
pnpm hackathon:start
```

Open `http://127.0.0.1:4317`.

The terminal prints one **Team token** and one **approver passphrase**. Use the Team token to sign in to the console and to call the local API. Keep the passphrase for REQUIRE_HUMAN in the browser. Do not commit tokens. Do not paste them into public chats or hosted agent services.

```bash
curl -sS http://127.0.0.1:4317/api/health
```

Expect `"ok":true`, `"sandbox":true`, `"realMoney":false`.

## 2. Synthetic demo (signed ADAP path)

In the browser, after signing in with the Team token:

| Scenario | Expected |
|---|---|
| pay-120 | ALLOW + synthetic execution + receipt |
| pay-750 | REQUIRE_HUMAN → approve with passphrase → one execution → replay rejected |
| pay-6000 | BLOCK + no execution |

## 3. Connect your agent (policy decision API)

Use the **same Team token** as `Authorization: Bearer …` against your local console.

Call `POST /api/gate` **before** your tool runs. Use the shared demo agent id `agt_hackathon_demo` — you do **not** need to edit source code.

| Tool example | Expected decision |
|---|---|
| `search_web` | ALLOW — your code may run a **mocked** search |
| `send_email` | REQUIRE_HUMAN — do not send mail; stop and wait |
| `delete_record` | BLOCK — do not delete anything |

```bash
export ADAP_URL=http://127.0.0.1:4317
export ADAP_TEAM_TOKEN='[REDACTED]'   # printed at startup

curl -sS -X POST "$ADAP_URL/api/gate" \
  -H "authorization: Bearer $ADAP_TEAM_TOKEN" \
  -H "content-type: application/json" \
  -H "x-adap-request: 1" \
  -d '{"agentId":"agt_hackathon_demo","tool":"search_web","args":{"q":"athens"}}'
```

`/api/gate` returns a decision. It does **not** execute your tool. Details and limits: [ADAP-FRAMEWORK-INTEGRATION.md](./ADAP-FRAMEWORK-INTEGRATION.md).

Examples: `examples/hackathon/gate.py`, `examples/hackathon/http_gate.mjs`, `examples/hackathon/plug.mjs`.
