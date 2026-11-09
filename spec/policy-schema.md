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
| `targetAgents` | string[] | yes | Agent roles governed, or `["*"]` for all. Entries are non-empty and must not contain whitespace |
| `defaultAction` | enum | yes | Used when no rule matches. `ALLOW` \| `BLOCK` \| `REQUIRE_HUMAN`. Missing or invalid is `BLOCK` with `ruleId: default_action_required` |
| `rules` | Rule[] | yes | Non-empty ordered rule list |

## Rule object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ruleId` | string | yes | Stable identifier for audit and logs |
| `action` | enum | yes | `ALLOW` \| `BLOCK` \| `REQUIRE_HUMAN` |
| `condition` | string | yes | Safe expression (see [deterministic-evaluation.md](./deterministic-evaluation.md)) |
| `alertSeverity` | enum | yes | `LOW` \| `MEDIUM` \| `CRITICAL` |

## Evaluation semantics

1. `agentRole` is required for evaluation. Omitted, empty, whitespace-only, null, or otherwise malformed identities return `BLOCK` with `ruleId: agent_not_in_scope` without evaluating rules. A well-formed role that is not in `targetAgents` (and `targetAgents` does not include `*`) also returns that `BLOCK`.
2. Evaluate every rule whose condition matches. The highest-priority action wins: `BLOCK`, then `REQUIRE_HUMAN`, then `ALLOW`. Document order breaks ties. A rule action outside those three does not execute. The reference evaluator returns `BLOCK` with `ruleId: unsupported_policy_action`.
3. If no rule matches: return `defaultAction`. Missing or invalid `defaultAction` is `BLOCK` with `ruleId: default_action_required`. The rule id is `default_allow` when that action is `ALLOW`. Otherwise it is `default_` plus the action in lower case, for example `default_block`.

## Decision output

Conforming evaluators return:

```typescript
interface PolicyDecision {
  matched: boolean
  action: 'ALLOW' | 'BLOCK' | 'REQUIRE_HUMAN'
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

## Unmatched actions

An unmatched rule falls through to `defaultAction`. That field is required. It is not an implicit allow.

`defaultAction: ALLOW` is a deliberate default-allow posture: any tool call that no rule matches is permitted. Sensitive and consequential workflows should use `BLOCK` as the unmatched action. `ALLOW` rules should name the actions they permit.

This is an explicit configuration choice in v0.1, not an omitted default. Existing documents that set `ALLOW` remain valid. A later policy-document major version could reject `defaultAction: ALLOW`. That change needs a new document major, a migration note, and a rewrite of those documents. v0.1 does not rewrite them.

## v0.1 actions

The reference execution protocol returns `ALLOW`, `BLOCK`, or `REQUIRE_HUMAN`. `DEFER` and `SIMULATE` appeared in earlier draft text. v0.1 has no deferred-execution state machine and no simulation interface, so the schema rejects both. A document that names them does not validate and cannot reach an executor. Only an explicit `ALLOW` can reach consequential execution. An unresolved `REQUIRE_HUMAN` does not.

Receipt format v1 still accepts `DEFER` and `SIMULATE` as recorded verbs so already issued receipts keep verifying. That record vocabulary is not permission to execute. See [policy-decision.md](./policy-decision.md) and [authorization-receipt.md](./authorization-receipt.md).

This is a draft correction inside v0.1. The execution protocol never implemented those two actions, so the protocol version is not bumped to 1.0. A future version may add them only with a specified state machine and a policy-document major version.

## Versioning

Breaking schema changes require a new major version of the policy document. A pin MUST include semver: `basic-agent-authority@1.0.0` (see [policy-federation.md](./policy-federation.md)). Removing `DEFER` and `SIMULATE` from the v0.1 schema invalidates draft documents that used them. Those documents were not executable. New documents use the three actions above.
