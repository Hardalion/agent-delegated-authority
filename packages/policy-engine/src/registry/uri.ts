/**
 * Version-pinned policy reference.
 * This draft does not define a URI scheme. This reference evaluator accepts `{policy-id}@{semver}`.
 * An optional `scheme://` prefix is ignored.
 * @example basic-agent-authority@1.0.0
 */

import { z } from 'zod'

export const policyPinSchema = z.object({
  policyId: z
    .string()
    .min(1)
    .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, 'policyId must be kebab-case'),
  version: z
    .string()
    .regex(/^\d+\.\d+\.\d+$/, 'version must be semver (e.g. 1.0.0)'),
  publisher: z.string().min(1).optional(),
})

export type PolicyPin = z.infer<typeof policyPinSchema>

const PIN_PATTERN =
  /^(?:[a-z][a-z0-9+.-]*:\/\/)?([a-z0-9]+(?:-[a-z0-9]+)*)@(\d+\.\d+\.\d+)(?:\/publisher\/([a-z0-9-]+))?$/i

export function isPolicyPin(value: string): boolean {
  return PIN_PATTERN.test(value.trim())
}

export function parsePolicyPin(raw: string): PolicyPin {
  const trimmed = raw.trim()
  const match = PIN_PATTERN.exec(trimmed)
  if (!match) {
    throw new Error(
      'Invalid policy pin. Required form: {policy-id}@{semver} (e.g. basic-agent-authority@1.0.0)'
    )
  }

  return policyPinSchema.parse({
    policyId: match[1].toLowerCase(),
    version: normalizeSemver(match[2]),
    publisher: match[3]?.toLowerCase(),
  })
}

export function formatPolicyPin(pin: PolicyPin): string {
  const base = `${pin.policyId}@${pin.version}`
  return pin.publisher ? `${base}/publisher/${pin.publisher}` : base
}

export function registryRefKey(pin: PolicyPin): string {
  return `${pin.policyId}@${pin.version}`
}

export function normalizeSemver(version: string): string {
  const parts = version.split('.')
  while (parts.length < 3) parts.push('0')
  return parts.slice(0, 3).join('.')
}

export function assertVersionPinned(
  requested: string,
  resolved: string,
  context: string
): void {
  if (normalizeSemver(requested) !== normalizeSemver(resolved)) {
    throw new Error(
      `${context}: requested version ${requested} does not match resolved ${resolved} (immutable pin violation)`
    )
  }
}
