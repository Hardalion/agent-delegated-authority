import { z } from 'zod'

export const ruleActionSchema = z.enum(['ALLOW', 'BLOCK', 'REQUIRE_HUMAN', 'DEFER', 'SIMULATE'])

export const alertSeveritySchema = z.enum(['LOW', 'MEDIUM', 'CRITICAL'])

/** Canonical policy id, kebab-case, matches the policy-id segment of a version pin. */
export const policyIdSchema = z
  .string()
  .min(1)
  .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, 'policyName must be kebab-case (e.g. basic-agent-authority)')

export const CANONICAL_BASIC_AGENT_AUTHORITY = 'basic-agent-authority' as const

export const ruleSchema = z.object({
  ruleId: z.string().min(1),
  action: ruleActionSchema,
  condition: z.string().min(1),
  alertSeverity: alertSeveritySchema,
})

export type PolicyRule = z.infer<typeof ruleSchema>

export const PolicySchema = z.object({
  version: z.string().min(1),
  policyName: policyIdSchema,
  description: z.string().optional(),
  targetAgents: z
    .array(
      z
        .string()
        .min(1, 'targetAgents entries must be non-empty')
        .refine((value) => value.trim() === value && !/\s/.test(value), {
          message: 'targetAgents entries must not contain whitespace',
        })
    )
    .min(1),
  rules: z.array(ruleSchema).min(1),
  /** Required. When no rule matches, this action is the decision. Missing is not ALLOW. */
  defaultAction: ruleActionSchema,
})

export type Policy = z.infer<typeof PolicySchema>
