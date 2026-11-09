# Framework integrations

Call the authorization gate before a tool runs.

1. Build the evaluation input: `toolName`, `toolArgs`, optional `agentRole`
2. Call `evaluateToolCall()` (or `adap-policy` in CI)
3. On `BLOCK`: do not execute
4. On `REQUIRE_HUMAN`: wait for a person, do not execute
5. On `ALLOW`: the caller may proceed

No framework SDK is required. Wrap the reference evaluator.

## TypeScript

```typescript
import { evaluateToolCall } from 'adap-policy'

export class ToolGate {
  constructor(private readonly policy: string) {}

  async beforeToolCall(toolName: string, toolArgs: Record<string, unknown>) {
    const decision = evaluateToolCall({
      policy: this.policy,
      toolName,
      toolArgs,
      agentRole: 'agt_reader',
    })

    if (decision.action === 'BLOCK') {
      throw new Error(`BLOCK [${decision.ruleId}]: ${decision.reason}`)
    }
    if (decision.action === 'REQUIRE_HUMAN') {
      return { deferred: true, ruleId: decision.ruleId, reason: decision.reason }
    }
    return { proceed: true }
  }
}
```

Wire this where tools are dispatched. The policy id in the example is `basic-agent-authority`.

## Python

Until a Python package exists, call the CLI:

```bash
adap-policy --policy basic-agent-authority --tool read --json
```

## Function calling

```typescript
const decision = evaluateToolCall({
  policy: 'basic-agent-authority',
  toolName: functionCall.name,
  toolArgs: JSON.parse(functionCall.arguments),
})
```

## CI

```bash
adap-policy --policy-uri basic-agent-authority@1.0.0 --tool apply --args "{\"amount\":800}" --json
# Exit 1 = BLOCK
```

## Model Context Protocol (MCP)

Guard MCP `tools/call` invocations directly with `McpToolGate` from `adap-policy`:

```typescript
import { McpToolGate, type McpToolCall } from 'adap-policy'

const gate = new McpToolGate({
  policy: 'basic-agent-authority',
  agentRole: 'agt_reader',
})

// Intercept incoming MCP CallToolRequest
const call: McpToolCall = {
  name: request.params.name,
  arguments: request.params.arguments,
}

const result = await gate.execute(call, async (args) => {
  // Underlying tool execution only runs when ADAP policy returns ALLOW
  return executeMyTool(call.name, args)
})

// On BLOCK or REQUIRE_HUMAN: result.isError is true, executor was not called.
// On ALLOW: result.content contains tool output, result._meta.adap has decision.
return result
```

## Contributing an adapter

Open a pull request with:

- A short wrapper
- A test with a known `BLOCK` and a known `ALLOW`
- A dependency on `adap-policy` only
