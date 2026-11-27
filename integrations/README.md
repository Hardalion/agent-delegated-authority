# Framework integrations

Call the authority path before a consequential tool runs. The path verifies the delegation chain and the signed intent, checks the nonce, evaluates the pinned policy, and emits a receipt.

`BLOCK` and an unresolved `REQUIRE_HUMAN` do not call the tool. Only `ALLOW` (including a later signed approval of a pending intent) may execute.

`evaluateToolCall()` is the policy check alone. It is documented below and does not provide these guarantees.

## TypeScript: full authority path

```typescript
import {
  BASIC_AGENT_AUTHORITY,
  BASIC_AGENT_AUTHORITY_URI,
  ImmutablePolicyResolver,
  NonceLedger,
  PendingAuthorizationStore,
  createIdentity,
  runAuthorityPath,
  signDelegation,
  signIntent,
} from 'adap-core'

const principal = createIdentity('prn_example')
const agent = createIdentity('agt_example')
const signer = createIdentity('reference-runtime')
const directory = new Map([
  [principal.id, principal.publicKey],
  [agent.id, agent.publicKey],
])

const issued = new Date().toISOString()
const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString()

const root = signDelegation(
  {
    delegation_id: 'del_root',
    issuer: principal.id,
    subject: agent.id,
    capabilities: [{ action: 'read', target: 'resource/*', delegable: false }],
    constraints: {},
    issued_at: issued,
    expires_at: expires,
  },
  principal
)

const intent = signIntent(
  {
    intent_id: 'int_1',
    actor: agent.id,
    delegation_chain: [root.delegation_id],
    action: 'read',
    target: 'resource/example',
    parameters: {},
    nonce: 'n_example_1',
    issued_at: issued,
    expires_at: expires,
  },
  agent
)

const policyResolver = new ImmutablePolicyResolver()
policyResolver.register(BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI)

const result = await runAuthorityPath({
  chain: [root],
  intent,
  directory,
  policy: BASIC_AGENT_AUTHORITY,
  policyUri: BASIC_AGENT_AUTHORITY_URI,
  policyResolver,
  ledger: new NonceLedger(),
  pendingStore: new PendingAuthorizationStore(),
  signer,
  // Operator revocation status. `revoked` and `unavailable` fail closed.
  // Omit the hook and the grant stays valid until expires_at.
  revocationCheck: (delegationId) => revocationStatus(delegationId),
  execute: (ctx) => callTool(ctx.action, ctx.target, ctx.parameters),
})

if (result.decision === 'BLOCK' || result.decision === 'REQUIRE_HUMAN') {
  // execute was not called
}
```

Production deployments replace the in-process nonce ledger and pending store with a shared atomic store (`adap-store-postgres` or equivalent). `max_amount` is a per-intent ceiling. It does not accumulate spend across intents.

The reference gateway process is `packages/adap-gateway`.

## Policy-only check

`evaluateToolCall()` answers whether a tool name and arguments match a policy document. It does not verify a delegation, a signature, a nonce, or a receipt. Use it for policy unit tests and for a pre-filter. Do not treat it as the authority boundary.

```typescript
import { evaluateToolCall } from 'adap-policy'

const decision = evaluateToolCall({
  policy: 'basic-agent-authority',
  toolName: 'read',
  toolArgs: {},
  agentRole: 'agt_reader',
})
```

### Python

Until a Python package exists, the CLI is the same policy-only check:

```bash
adap-policy --policy basic-agent-authority --tool read --json
```

### CI

```bash
adap-policy --policy-uri basic-agent-authority@1.0.0 --tool apply --args "{\"amount\":800}" --json
# Exit 1 = BLOCK
```

## Model Context Protocol (MCP)

Two claim levels. Do not mix them.

| Claim | What it checks |
| --- | --- |
| Policy-only helper | `McpToolGate` / `evaluateToolCall` on tool name and arguments |
| Authority-enforcing binding | Signed intent, delegation chain, nonce, policy pin, receipt. Normative text: `spec/mcp-binding.md` |

```typescript
import { McpToolGate, type McpToolCall } from 'adap-policy'

const gate = new McpToolGate({
  policy: 'basic-agent-authority',
  agentRole: 'agt_reader',
})

const call: McpToolCall = {
  name: request.params.name,
  arguments: request.params.arguments,
}

// Policy-only. This is not an ADAP MCP binding.
const result = await gate.execute(call, async (args) => executeMyTool(call.name, args))
```

## Contributing an adapter

Open a pull request with a short wrapper and a test that shows one `BLOCK` and one `ALLOW`.

- A policy-only adapter depends on `adap-policy`.
- An authority adapter depends on `adap` and calls `runAuthorityPath` (or the gateway) before the tool runs.
