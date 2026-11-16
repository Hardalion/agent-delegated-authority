import { assertCanonicalTarget, type RunAuthorityPathInput } from 'adap'
import { z } from 'zod'

const GrantSchema = z.object({
  issuerId: z.string().min(1),
  action: z.string().regex(/^[a-z][a-z0-9._-]{0,127}$/),
  target: z.string().min(1),
}).strict()

/** Operator configuration. Every capability in a root must be covered. */
export function createRootAuthority(
  configuration: unknown,
  directory: ReadonlyMap<string, string>,
): NonNullable<RunAuthorityPathInput['rootAuthority']> {
  const grants = z.array(GrantSchema).min(1).parse(configuration)
  for (const grant of grants) {
    assertCanonicalTarget(grant.target, { grant: true })
    if (!directory.has(grant.issuerId)) {
      throw new Error('root grant issuer is absent from the identity directory')
    }
  }

  return {
    allowSelfIssuedRoot: false,
    mayIssueRoot: ({ issuerId, subjectId, capabilities }) =>
      issuerId !== subjectId && capabilities.length > 0 && capabilities.every((capability) =>
        grants.some((grant) =>
          grant.issuerId === issuerId && grant.action === capability.action &&
          coversTarget(grant.target, capability.target),
        ),
      ),
  }
}

function coversTarget(granted: string, requested: string): boolean {
  if (granted === requested) return true
  if (!granted.endsWith('/*')) return false
  const prefix = granted.slice(0, -1)
  const rest = requested.slice(prefix.length)
  return requested.startsWith(prefix) && rest.length > 0 && !rest.includes('/')
}
