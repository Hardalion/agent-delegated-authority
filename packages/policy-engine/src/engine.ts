import { readFileSync } from 'node:fs'
import { parse as parseYaml } from 'yaml'
import { PolicySchema, type Policy, type PolicyRule } from './schema.js'
import {
  buildEvaluationContext,
  evaluateCondition,
  type EvaluationContext,
} from './evaluator.js'
import { BUNDLED_POLICIES, normalizePolicyReference } from './policies/bundled.js'

export type PolicyAction = PolicyRule['action']

export interface PolicyDecision {
  readonly matched: boolean
  readonly action: PolicyAction
  readonly ruleId: string
  readonly reason: string
  readonly alertSeverity: PolicyRule['alertSeverity']
}

export interface EvaluatePolicyInput {
  readonly policy: Policy | string
  readonly context: EvaluationContext
  readonly agentRole?: string
}

/** Load a policy document from a filesystem path. */
export function loadPolicyFromFile(path: string): Policy {
  const raw = readFileSync(path, 'utf8')
  return parsePolicyDocument(raw)
}

let bundledPolicies: Record<string, Policy> | null = null

function getBundledPolicies(): Record<string, Policy> {
  if (!bundledPolicies) {
    bundledPolicies = { ...BUNDLED_POLICIES }
  }
  return bundledPolicies
}

/** Parse YAML or JSON policy document into validated Policy. */
export function parsePolicyDocument(source: string): Policy {
  const trimmed = source.trim()
  const doc = trimmed.startsWith('{') ? JSON.parse(trimmed) : parseYaml(source)
  return PolicySchema.parse(doc)
}

/** Resolve policy by name, inline object, or raw YAML/JSON string. */
export function resolvePolicy(policy: Policy | string): Policy {
  if (typeof policy !== 'string') return policy

  const normalized = normalizePolicyReference(policy)
  const bundled = getBundledPolicies()[normalized]
  if (bundled) return bundled

  if (policy.includes('\n') || policy.trim().startsWith('{')) {
    return parsePolicyDocument(policy)
  }

  throw new Error(`Unknown policy: ${policy}`)
}

export function listBundledPolicyNames(): string[] {
  return Object.keys(getBundledPolicies())
}

function agentMatchesPolicy(policy: Policy, agentRole?: string): boolean {
  if (policy.targetAgents.includes('*')) return true
  if (!agentRole) return true
  return policy.targetAgents.includes(agentRole)
}

const ACTION_PRIORITY: Record<PolicyAction, number> = {
  BLOCK: 5,
  REQUIRE_HUMAN: 4,
  DEFER: 3,
  SIMULATE: 2,
  ALLOW: 1,
}

/** Evaluate all rules; highest-priority matching action wins (BLOCK > REQUIRE_HUMAN > DEFER > SIMULATE > ALLOW). */
export function evaluatePolicy(input: EvaluatePolicyInput): PolicyDecision {
  const policy = resolvePolicy(input.policy)

  if (!agentMatchesPolicy(policy, input.agentRole ?? input.context.agentRole)) {
    return {
      matched: false,
      action: 'BLOCK',
      ruleId: 'agent_not_in_scope',
      reason: 'Agent role not targeted by policy',
      alertSeverity: 'CRITICAL',
    }
  }

  const matches: PolicyDecision[] = []

  for (const rule of policy.rules) {
    if (evaluateCondition(rule.condition, input.context)) {
      matches.push({
        matched: true,
        action: rule.action,
        ruleId: rule.ruleId,
        reason: `Rule ${rule.ruleId} matched: ${rule.condition}`,
        alertSeverity: rule.alertSeverity,
      })
    }
  }

  if (matches.length === 0) {
    const action = policy.defaultAction ?? 'ALLOW'
    return {
      matched: false,
      action,
      ruleId: action === 'ALLOW' ? 'default_allow' : `default_${action.toLowerCase()}`,
      reason:
        action === 'ALLOW' ? 'No rules matched' : `No rules matched; defaultAction ${action}`,
      alertSeverity: action === 'BLOCK' || action === 'REQUIRE_HUMAN' ? 'CRITICAL' : 'LOW',
    }
  }

  return matches.reduce((best, current) =>
    ACTION_PRIORITY[current.action] > ACTION_PRIORITY[best.action] ? current : best
  )
}

export function evaluateToolCall(input: {
  policy: Policy | string
  toolName: string
  toolArgs?: Record<string, unknown>
  agentRole?: string
  /** Non-secret authz context for `context.*` conditions. */
  evaluationContext?: Record<string, unknown>
}): PolicyDecision {
  return evaluatePolicy({
    policy: input.policy,
    agentRole: input.agentRole,
    context: buildEvaluationContext({
      toolName: input.toolName,
      toolArgs: input.toolArgs,
      agentRole: input.agentRole,
      context: input.evaluationContext,
    }),
  })
}

export function evaluateInvocation(input: {
  policy: Policy | string
  args: unknown[]
  agentRole?: string
}): PolicyDecision {
  const first = input.args[0]
  const payload = typeof first === 'string' ? first : undefined
  const toolCall =
    first != null && typeof first === 'object' && !Array.isArray(first)
      ? (first as { toolName?: string; name?: string; args?: Record<string, unknown> })
      : undefined

  const toolName = toolCall?.toolName ?? toolCall?.name
  const toolArgs = toolCall?.args

  return evaluatePolicy({
    policy: input.policy,
    agentRole: input.agentRole,
    context: buildEvaluationContext({
      toolName,
      toolArgs,
      payload,
      agentRole: input.agentRole,
    }),
  })
}

/** Evaluate a payload against a policy document. Default is the bundled example. */
export function evaluateExecutionPayload(input: {
  args: Record<string, unknown>
  agentRole?: string
  policy?: Policy | string
}): PolicyDecision {
  return evaluatePolicy({
    policy: input.policy ?? 'basic-agent-authority',
    agentRole: input.agentRole,
    context: buildEvaluationContext({ args: input.args, agentRole: input.agentRole }),
  })
}

/** Reset bundled policy cache (tests). */
export function resetBundledPoliciesForTests(): void {
  bundledPolicies = null
}
