# Deterministic policy evaluation

Normative property: **same input → same output, always, with no side effects.**

## Guarantee

A conforming evaluator:

1. Does **not** call `eval()`, `Function()`, or dynamic code execution
2. Does **not** perform network I/O, filesystem access, or clock reads during evaluation
3. Does **not** mutate input context or global state
4. Parses conditions into a fixed AST evaluated with pure functions
5. Returns a `PolicyDecision` object fully determined by `(policy document, agentRole, evaluation context)`

## Formal inputs

```
evaluatePolicy({
  policy: Policy | policyId | YAML path,
  agentRole?: string,
  context: { tool?: { name }, args?: Record<string, unknown>, ... }
}) → PolicyDecision
```

`PolicyDecision` fields: `action`, `ruleId`, `matched`, `alertSeverity`, `policyName`, `reason`.

## Determinism test contract

Any third party can verify:

```typescript
const input = {
  policy: 'basic-agent-authority',
  toolName: 'read',
  toolArgs: {},
}

const a = evaluateToolCall(input)
const b = evaluateToolCall(input)
assert.deepEqual(a, b) // always true
```

Reference tests: `packages/policy-engine/src/engine.test.ts`.

## Non-determinism boundaries (explicit)

| Component | Deterministic? | Notes |
|-----------|----------------|-------|
| Condition evaluator | **Yes** | Pure |
| Bundled example resolution | **Yes** | Static local document |
| Policy id case | **Yes** | References are lowercased before lookup |

Offline evaluation uses a bundled example id or a local YAML file.

## Rule precedence

Every matching rule is a candidate. The highest-priority action wins: `BLOCK`, then `REQUIRE_HUMAN`, then `DEFER`, then `SIMULATE`, then `ALLOW`. Document order breaks ties. If no rule matches, the result is `defaultAction`, or `ALLOW` when `defaultAction` is absent. The rule id is `default_allow` only when that action is `ALLOW`. Otherwise it is `default_` plus the action in lower case.

Agent scope fails closed. If `agentRole` is not in `targetAgents` (and `targetAgents` is not `*`): `BLOCK` with `ruleId: agent_not_in_scope`, and no rule is evaluated.

## Version pinning

Policy documents carry `version` and `policyName` (kebab-case). A pin is `{policy-id}@{semver}`, for example `basic-agent-authority@1.0.0`. The URI scheme is implementation-defined. Resolution of a pin is implementation-defined. An unresolved pin fails closed.
