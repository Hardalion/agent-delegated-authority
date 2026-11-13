# ADAP Framework Integration

**ADAP is the common authority and policy interface — not another agent framework.**

Bring your own agent stack. Keep your LLM and tools. Call ADAP before consequential actions.

For this hackathon, ADAP runs **locally** on your computer (`pnpm hackathon:start` → `http://127.0.0.1:4317`).

```
Agent / Framework → ADAP Interface → Policy Decision → (your code continues only on ALLOW)
```

| Decision | What you do |
|---|---|
| **ALLOW** | Your agent may run its **own** tool implementation (use mocks for the hackathon). |
| **REQUIRE_HUMAN** | Stop. Do not run the tool. Show the decision and wait for a person. |
| **BLOCK** | Do not run the tool. |

Synthetic only: `sandbox: true`, `realMoney: false`.

---

## Two different surfaces (do not conflate them)

### 1. Framework-neutral policy decision API — `POST /api/gate`

Use this to wrap tools in LangGraph, CrewAI, AutoGen, OpenAI tool calls, custom Python/TypeScript, etc.

What it **does**:

- Accepts `agentId`, `tool`, and flat `args`
- Evaluates a weekend demo policy (`evaluateToolCall`)
- Returns `ALLOW` / `REQUIRE_HUMAN` / `BLOCK`
- Sets `runTool: true` only when the decision is `ALLOW`
- Always returns `executed: false` — **this endpoint never runs your tool**

What it **is not**:

- Not an out-of-process enforcement boundary that can stop a malicious agent that ignores the response
- Not the full signed ADAP path (no signed delegation chain / signed intent verification on this endpoint)
- Not a complete human-approval ticket system: REQUIRE_HUMAN means “your agent must stop”; it does **not** create a pending approval you can resume through `/api/approvals/...` for that tool call
- Not cryptographic agent identity: `agt_hackathon_demo` is a **shared demo policy id**, not a verified key-backed agent

Argument limits: top-level `args` values may be string, finite number, or boolean only. Nested objects, arrays, and `null` are rejected. Keep examples flat.

Auth: the same **Team token** printed by `pnpm hackathon:start` (`Authorization: Bearer …`). Header `x-adap-request: 1` is required on mutating requests.

### 2. Signed ADAP sandbox workflow (browser console)

Scenarios such as `pay-120` / `pay-750` / `pay-6000` exercise signed intents, policy, human approval with the approver passphrase, receipts, and replay protection. Use that UI to demonstrate the full authority story. Do not claim that `/api/gate` alone is that story.

---

## Local setup

1. `pnpm hackathon:start`
2. Copy the printed **Team token**
3. Use agent id `agt_hackathon_demo` — **no source edits**
4. Call `/api/gate` before tools run

## Request / response

```json
{
  "agentId": "agt_hackathon_demo",
  "tool": "search_web",
  "args": { "q": "athens agents" }
}
```

```json
{
  "action": "ALLOW",
  "ruleId": "…",
  "reason": "…",
  "executed": false,
  "runTool": true,
  "sandbox": true,
  "realMoney": false
}
```

Your code must check `action` (or `runTool`) and only then invoke a **mocked** tool.

## Three examples (mocked tools)

| Tool | Expected |
|---|---|
| `search_web` | ALLOW |
| `send_email` | REQUIRE_HUMAN |
| `delete_record` | BLOCK |

### cURL

```bash
export ADAP_URL=http://127.0.0.1:4317
export ADAP_TEAM_TOKEN='[REDACTED]'   # Team token from startup

curl -sS -X POST "$ADAP_URL/api/gate" \
  -H "authorization: Bearer $ADAP_TEAM_TOKEN" \
  -H "content-type: application/json" \
  -H "x-adap-request: 1" \
  -d '{"agentId":"agt_hackathon_demo","tool":"search_web","args":{"q":"athens"}}'
```

### JavaScript

```javascript
const base = process.env.ADAP_URL ?? 'http://127.0.0.1:4317'
const token = process.env.ADAP_TEAM_TOKEN // printed at startup — never hardcode
if (!token) throw new Error('Set ADAP_TEAM_TOKEN')

async function checkGate(tool, args) {
  const res = await fetch(`${base}/api/gate`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'x-adap-request': '1',
    },
    body: JSON.stringify({ agentId: 'agt_hackathon_demo', tool, args }),
  })
  const decision = await res.json()
  if (!res.ok) throw new Error(decision?.error?.message ?? res.statusText)
  return decision
}

async function runTool(tool, args, handler) {
  const decision = await checkGate(tool, args)
  if (decision.action !== 'ALLOW' || decision.runTool !== true) {
    console.log('stop:', decision.action, decision.reason)
    return { stopped: true, decision }
  }
  // ALLOW only — handler must be a mock for the hackathon
  return { stopped: false, decision, result: await handler(args) }
}

await runTool('search_web', { q: 'athens' }, async () => ({ hits: [] }))
await runTool('send_email', { to: 'demo@example.com' }, async () => {
  throw new Error('must not run')
})
await runTool('delete_record', { id: 'rec_1' }, async () => {
  throw new Error('must not run')
})
```

Runnable copy: [`examples/hackathon/http_gate.mjs`](../examples/hackathon/http_gate.mjs).

### Python

```python
import os, urllib.request, json

base = os.environ.get("ADAP_URL", "http://127.0.0.1:4317").rstrip("/")
token = os.environ.get("ADAP_TEAM_TOKEN")  # printed at startup — never hardcode
if not token:
    raise SystemExit("Set ADAP_TEAM_TOKEN")

def check_gate(tool: str, args: dict) -> dict:
    req = urllib.request.Request(
        f"{base}/api/gate",
        data=json.dumps(
            {"agentId": "agt_hackathon_demo", "tool": tool, "args": args}
        ).encode(),
        headers={
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            "x-adap-request": "1",
        },
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.load(resp)

def run_tool(tool: str, args: dict, handler):
    decision = check_gate(tool, args)
    if decision.get("action") != "ALLOW" or decision.get("runTool") is not True:
        print("stop:", decision.get("action"), decision.get("reason"))
        return {"stopped": True, "decision": decision}
    # ALLOW only — handler must be a mock for the hackathon
    return {"stopped": False, "decision": decision, "result": handler(args)}

run_tool("search_web", {"q": "athens"}, lambda _: {"hits": []})
run_tool("send_email", {"to": "demo@example.com"}, lambda _: (_ for _ in ()).throw(RuntimeError("must not run")))
run_tool("delete_record", {"id": "rec_1"}, lambda _: (_ for _ in ()).throw(RuntimeError("must not run")))
```

Runnable copy: [`examples/hackathon/http_gate.py`](../examples/hackathon/http_gate.py), [`examples/hackathon/gate.py`](../examples/hackathon/gate.py).

Named products (LangGraph, CrewAI, AutoGen, …) are examples of **external** systems. This guide does not claim native vendor integrations.

## Protocol

Normative ADAP requirements: [../spec/](../spec/).
