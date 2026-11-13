# Deterministic policy evaluation

Normative property: **same input → same output, always, with no side effects.**

## Guarantee

A conforming evaluator:

1. Does **not** call `eval()`, `Function()`, or dynamic code execution
2. Does **not** perform network I/O, filesystem access, or clock reads during evaluation
3. Does **not** mutate input context or global state
4. Parses conditions into a fixed AST evaluated with pure functions
5. Returns a `PolicyDecision` object fully determined by `(policy document, agentRole, evaluation context)`
6. For `>`, `<`, `>=`, and `<=`, both operands must already be finite numbers. `null`, booleans, strings, missing values, `NaN`, and infinities do not coerce. `NaN` and infinities are `BLOCK` with rule id `amount_not_finite`. Any other non-number is `BLOCK` with rule id `numeric_comparison_rejected`. Neither falls through to `defaultAction: ALLOW`. `==` and `!=` stay strict equality and are not forced to be numeric
7. A condition that fails to parse or evaluate is `BLOCK` with rule id `condition_evaluation_error`. The reason is fixed and does not include the condition text or a stack. Loading an invalid policy document still throws, so a bad document is not reported as a runtime condition error

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

Every matching rule is a candidate. The highest-priority action wins: `BLOCK`, then `REQUIRE_HUMAN`, then `ALLOW`. Document order breaks ties. If no rule matches, the result is `defaultAction`. Missing or invalid `defaultAction` is `BLOCK` with `ruleId: default_action_required`. The rule id is `default_allow` only when that action is `ALLOW`. Otherwise it is `default_` plus the action in lower case. `DEFER` and `SIMULATE` are not actions in v0.1.

Property paths may be arbitrarily deep (`args.user.profile.account.id`). Resolution uses own properties only. Inherited properties and the names `__proto__`, `constructor`, and `prototype` do not resolve. `.contains()` applies to strings and arrays at the end of such a path. A missing or null intermediate does not continue the walk.

## Structured context and freeform text

Tool arguments reach the evaluator as a plain object on `args` and `tool.args`. `buildEvaluationContext` drops a fixed set of chat-shaped keys (`prompt`, `messages`, and similar) so those strings are not sitting on the context. That list is not a security boundary against prompt injection. This evaluator does not execute natural language and does not call a model.

A renamed freeform field is ordinary data. It affects a decision only when a policy condition names that field. A global whitelist of argument keys would reject legitimate business fields (`amount`, `quantity`, `currency`, and others) that policies compare. The boundary is: authorization context is structured data the policy author chose to read; untrusted prose is not an instruction to the evaluator. Tool-specific context providers may omit fields before building that object. The generic evaluator does not invent a universal argument whitelist.

Agent scope fails closed. Omitted, empty, whitespace-only, null, or malformed `agentRole` values are out of scope even when `targetAgents` is `["*"]`. A well-formed role that is not in `targetAgents` (and `targetAgents` is not `*`): `BLOCK` with `ruleId: agent_not_in_scope`, and no rule is evaluated.

## Version pinning

Policy documents carry `version` and `policyName` (kebab-case). A pin is `{policy-id}@{semver}`, for example `basic-agent-authority@1.0.0`. The URI scheme is implementation-defined. Resolution of a pin is implementation-defined. An unresolved pin fails closed.
