import { assertCanonicalTarget, type DirectoryKeyRecord, type RunAuthorityPathInput } from 'adap'
import { z } from 'zod'

const GrantSchema = z.object({
  issuerId: z.string().min(1),
  action: z.string().regex(/^[a-z][a-z0-9._-]{0,127}$/),
  target: z.string().min(1),
}).strict()

/** Operator configuration. Every capability in a root must be covered. */
function issuerPresent(
  directory: ReadonlyMap<string, string> | { list(identityId: string): readonly Pick<DirectoryKeyRecord, 'status'>[] },
  issuerId: string,
): boolean {
  if (directory instanceof Map) return directory.has(issuerId)
  const listed = directory as { list(identityId: string): readonly Pick<DirectoryKeyRecord, 'status'>[] }
  return listed.list(issuerId).some((key) => key.status === 'active')
}

export function createRootAuthority(
  configuration: unknown,
  directory: ReadonlyMap<string, string> | { list(identityId: string): readonly Pick<DirectoryKeyRecord, 'status'>[] },
): NonNullable<RunAuthorityPathInput['rootAuthority']> {
  const grants = z.array(GrantSchema).min(1).parse(configuration)
  for (const grant of grants) {
    assertCanonicalTarget(grant.target, { grant: true })
    if (!issuerPresent(directory, grant.issuerId)) {
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
