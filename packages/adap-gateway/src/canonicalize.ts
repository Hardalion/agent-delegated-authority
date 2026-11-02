import { assertCanonicalTarget } from 'adap'

/** Canonical tool/action name: lowercase, trimmed, no whitespace. */
export function canonicalizeAction(action: unknown): string {
  if (typeof action !== 'string') throw new Error('action must be a string')
  const trimmed = action.trim().toLowerCase()
  if (!/^[a-z][a-z0-9._-]{0,127}$/.test(trimmed)) {
    throw new Error('action is not canonical')
  }
  return trimmed
}

export function canonicalizeTarget(target: unknown): string {
  if (typeof target !== 'string') throw new Error('target must be a string')
  return assertCanonicalTarget(target)
}

/**
 * Freeze a shallow copy of authorized parameters so post-validation mutation
 * cannot alter the downstream request object held by the gateway.
 */
export function freezeAuthorizedParameters(
  parameters: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  return Object.freeze({ ...parameters })
}
