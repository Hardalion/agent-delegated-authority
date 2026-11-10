# Deterministic policy evaluation

Normative property: **same input → same output, always, with no side effects.**

## Guarantee

A conforming evaluator:

1. Does **not** call `eval()`, `Function()`, or dynamic code execution
2. Does **not** perform network I/O, filesystem access, or clock reads during evaluation
3. Does **not** mutate input context or global state
4. Parses conditions into a fixed AST evaluated with pure functions
5. Returns a `PolicyDecision` object fully determined by `(policy document, agentRole, evaluation context)`
6. Rejects a numeric comparison when either operand is `NaN`, `Infinity`, or `-Infinity`. The decision is `BLOCK` with rule id `amount_not_finite`. A non-finite value must not fall through to `defaultAction: ALLOW`

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

Every matching rule is a candidate. The highest-priority action wins: `BLOCK`, then `REQUIRE_HUMAN`, then `DEFER`, then `SIMULATE`, then `ALLOW`. Document order breaks ties. If no rule matches, the result is `defaultAction`. Missing or invalid `defaultAction` is `BLOCK` with `ruleId: default_action_required`. The rule id is `default_allow` only when that action is `ALLOW`. Otherwise it is `default_` plus the action in lower case.

Agent scope fails closed. Omitted, empty, whitespace-only, null, or malformed `agentRole` values are out of scope even when `targetAgents` is `["*"]`. A well-formed role that is not in `targetAgents` (and `targetAgents` is not `*`): `BLOCK` with `ruleId: agent_not_in_scope`, and no rule is evaluated.

## Missing and non-numeric operands (proposed)

> Status: proposed in review. The reference evaluator at `bc5ae76` behaves differently.

In the reference `compare()`, a missing `args.amount` becomes `Number(undefined)`, which is `NaN`, and the comparison returns `false`. A `BLOCK` rule such as `tool.name == 'purchase' && args.amount > 500` therefore does not match when `amount` is absent or renamed, and a lower-priority `REQUIRE_HUMAN` or `ALLOW` rule wins. `null`, `[]` and `""` coerce to `0`. On the policy-only integration path (`integrations/README.md`) there is no delegation check behind this.

Proposed:

1. An ordered comparison (`>`, `<`, `>=`, `<=`) whose operand is missing, or is not a finite number, is an evaluation error. The decision is `BLOCK` with rule id `operand_invalid`. This extends rule 6 above from non-finite values to absent and non-numeric ones.
2. Add `exists(path)`, `!` and `||` to the grammar so authors can write explicit guards.

## Evaluation context (proposed)

The reference path calls the evaluator with the tool name, the arguments, and the actor id as `agentRole`. Rules cannot see `intent.target`, the principal, the delegation chain, or the terminal constraints. A policy cannot say "purchases at `airline/example` need a person; anywhere else is blocked".

`omitFreeformArgs` also removes arguments named `prompt`, `system`, `messages`, `instruction` and others before evaluation. The executor still receives them. A policy cannot constrain a tool whose consequential input has one of those names.

Proposed: the context includes `target`, `principal`, `chain` and `constraints`, and the evaluator sees every argument the executor will receive.

## Version pinning

Policy documents carry `version` and `policyName` (kebab-case). A pin is `{policy-id}@{semver}`, for example `basic-agent-authority@1.0.0`. The URI scheme is implementation-defined. Resolution of a pin is implementation-defined. An unresolved pin fails closed.
