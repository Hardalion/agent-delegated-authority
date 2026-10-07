# Policy document schema

**Status:** Public Draft (v0.1)
**Media type:** `application/x-adap-policy+json` or YAML equivalent

Policies are JSON objects (YAML is a serialization). Conforming documents MUST validate against this schema.

## Top-level fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | yes | Policy document semver (`major.minor.patch`) |
| `policyName` | string | yes | Stable id, **kebab-case** (`^[a-z0-9]+(?:-[a-z0-9]+)*$`) |
| `description` | string | no | Human-readable summary |
| `targetAgents` | string[] | yes | Agent roles governed, or `["*"]` for all |
| `defaultAction` | enum | no | Used when no rule matches. `ALLOW` \| `BLOCK` \| `REQUIRE_HUMAN` \| `DEFER` \| `SIMULATE`. Absent means `ALLOW` |
| `rules` | Rule[] | yes | Non-empty ordered rule list |

## Rule object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ruleId` | string | yes | Stable identifier for audit and logs |
| `action` | enum | yes | `ALLOW` \| `BLOCK` \| `REQUIRE_HUMAN` \| `DEFER` \| `SIMULATE` |
| `condition` | string | yes | Safe expression (see [deterministic-evaluation.md](./deterministic-evaluation.md)) |
| `alertSeverity` | enum | yes | `LOW` \| `MEDIUM` \| `CRITICAL` |

## Evaluation semantics

1. If `agentRole` is provided and not in `targetAgents` (and `targetAgents` does not include `*`): return `BLOCK` with `ruleId: agent_not_in_scope` without evaluating rules. An agent outside the policy is not authorized.
2. Evaluate every rule whose condition matches. The highest-priority action wins: `BLOCK`, then `REQUIRE_HUMAN`, then `DEFER`, then `SIMULATE`, then `ALLOW`. Document order breaks ties.
3. If no rule matches: return `defaultAction`, or `ALLOW` when `defaultAction` is absent. The rule id is `default_allow` when that action is `ALLOW`. Otherwise it is `default_` plus the action in lower case, for example `default_block`.

## Decision output

Conforming evaluators return:

```typescript
interface PolicyDecision {
  matched: boolean
  action: 'ALLOW' | 'BLOCK' | 'REQUIRE_HUMAN' | 'DEFER' | 'SIMULATE'
  ruleId: string
  reason: string
  alertSeverity: 'LOW' | 'MEDIUM' | 'CRITICAL'
  policyName?: string
}
```

## Example

```yaml
version: "1.0.0"
policyName: basic-agent-authority
description: Example policy for protocol semantics
targetAgents: ["*"]
defaultAction: BLOCK
rules:
  - ruleId: read_allow
    action: ALLOW
    condition: "tool.name == 'read'"
    alertSeverity: LOW
```

## Reference implementation

The Zod schema in `packages/policy-engine` (`PolicySchema`) is one conformance harness for this draft. Another implementation may use its own.

## Versioning

Breaking schema changes require a new major version. A pin MUST include semver: `basic-agent-authority@1.0.0` (see [policy-federation.md](./policy-federation.md)).
